#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Speed/hit-rate experiment runner for domain2email attacks.

Iteration 3 changes vs iteration 2:
  - FIXED:   schema timeout=(2,3) instead of =3 — was silently failing on slow servers
             (universo88.com.br had email on page, schema missed it due to connect timeout)
  - FIXED:   schema reduced to homepage + /pages/contact + /pages/contact-us only
             (other sub-pages never contributed a hit; dropping them saves time)
  - DROPPED: mailto attack — merged into schema (same logic, redundant)
  - FIXED:   whois deny list expanded with registrar proxy domains
             (shopify registrar, wix-domains, godaddy, namecheap, etc.)
  - TUNED:   schema uses as_completed + early exit — stops fetching once email found

Usage:
  python3 experiment.py
  python3 experiment.py --workers 10
  python3 experiment.py --attack dmarc,schema,smtp
"""

import argparse
import json
import re
import smtplib
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("WARNING: pip install dnspython")

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("WARNING: pip install python-whois  (for whois attack)")

# ── Config ─────────────────────────────────────────────────────────────────────
DOMAINS = [
    "heretoy.com",
    "solitaire-fashion.com",
    "pochigoods.com",
    "universo88.com.br",
    "molten.world",
    "thecaliforniacandleco.com",
    "devilstheangel.com",
    "northstarlighting.net",
    "threadedgray.com",
    "tagliariol.shop",
    "robertocalzature.it",
]

HTTP_CONNECT_TO = 2   # connect timeout — was 3 (single), silently failed on slow servers
HTTP_READ_TO    = 3   # read timeout — separate budget from connect
SMTP_TO    = 2
DNS_TO     = 3
WORKERS    = len(DOMAINS)
SMTP_PORTS = [25, 587]
UA         = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36")
CATCHALL_PROBE = "zz-no-exist-xq7r-probe"
EMAIL_RE       = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
ROLE_GUESSES   = ["info", "support", "hello", "contact", "sales",
                  "shop", "team", "care", "help", "admin"]
DENY_SUFFIXES  = (
    "@sentry.io","@example.com","@yourdomain.com","@domain.com",
    "@shopify.com","@myshopify.com","@klaviyo.com","@sendgrid.net",
    "@googletagmanager.com","@google-analytics.com",
)
DENY_DMARC_DOMAINS = {
    "mailhardener.com","dmarcian.com","dmarc.postmarkapp.com","agari.com",
    "valimail.com","easydmarc.com","uriports.com","mxtoolbox.com",
    "dmarcanalyzer.com","dmarcreport.com","postmark.com","proofpoint.com",
    "redsift.io","reportdmarc.nl","brevo.com",
}
DENY_DMARC_LOCALS = {
    "abuse","postmaster","noreply","no-reply","mailer-daemon","hostmaster",
    "webmaster","dmarc","dmarc-reports","dmarc_rua","dmarc_ruf",
    "rua","ruf","bounces","bounce",
}
VALID_TLDS = {
    "com","net","org","io","co","me","store","shop","uk","us","au","de","fr",
    "nl","se","no","dk","fi","be","at","ch","es","it","pt","ca","nz","ie",
    "online","tech","digital","app","dev","ai","studio","agency","media",
    "health","care","life","art","email","club","site","link","social",
    "photography","consulting","solutions","software","global","group",
    "clothing","jewelry","beauty","fitness","coffee","garden","pet","food",
    "br","jp","cn","in","mx","ar","cl","co","pe","ec","ru","ua","pl","cz",
    "hu","ro","sk","bg","hr","rs","si","lt","lv","ee","tr","gr","cy",
}

SHOPIFY_PAGES = [
    "/pages/contact",
    "/pages/contact-us",
    "/policies/contact-information",  # standard Shopify policy page — high hit rate
]

# ── Helpers ────────────────────────────────────────────────────────────────────
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def log(domain, attack, msg):
    print(f"[{now_iso()}] [{domain:<30}] [{attack:<14}] {msg}", flush=True)

def is_valid_email(e):
    if not e or e.count("@") != 1: return False
    local, dom = e.split("@", 1)
    if not (2 <= len(local) <= 64): return False  # min 2: catches oi@, hi@, me@
    if not dom or "." not in dom: return False
    tld = dom.rsplit(".", 1)[-1].lower()
    return tld in VALID_TLDS

def dns_txt(name):
    if not HAS_DNS: return []
    try:
        return [str(r) for r in dns.resolver.resolve(name, "TXT", lifetime=DNS_TO)]
    except Exception:
        return []

def dns_mx(domain):
    if not HAS_DNS: return None
    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=DNS_TO)
        best = min(records, key=lambda r: r.preference)
        return str(best.exchange).rstrip(".")
    except Exception:
        try:
            parts = domain.split(".")
            if len(parts) > 2:
                apex = ".".join(parts[-2:])
                records = dns.resolver.resolve(apex, "MX", lifetime=DNS_TO)
                best = min(records, key=lambda r: r.preference)
                return str(best.exchange).rstrip(".")
        except Exception:
            pass
    return None

def decode_cloudflare_email(encoded):
    key = int(encoded[:2], 16)
    return "".join(chr(int(encoded[i:i+2], 16) ^ key) for i in range(2, len(encoded), 2))

def extract_cloudflare_emails(html):
    found = []
    for encoded in re.findall(r'data-cfemail="([0-9a-f]+)"', html, re.I):
        try:
            e = decode_cloudflare_email(encoded).lower()
            if is_valid_email(e):
                found.append(e)
        except Exception:
            pass
    return found

def scrape_emails_from_html(html, domain_filter=None):
    """Extract all candidate emails from raw HTML (mailto links, text, Cloudflare)."""
    found = []
    # Cloudflare-protected
    found.extend(extract_cloudflare_emails(html))
    # Explicit mailto: href links
    for href in re.findall(r'href=["\']mailto:([^"\'?\s]+)', html, re.I):
        found.append(href.lower().strip())
    # Plain email pattern in text
    for e in EMAIL_RE.findall(html):
        found.append(e.lower())
    # Deduplicate, validate, filter noise
    seen = set()
    clean = []
    for e in found:
        if e in seen: continue
        seen.add(e)
        if not is_valid_email(e): continue
        if any(e.endswith(s) for s in DENY_SUFFIXES): continue
        if "'" in e or "{" in e or "%" in e: continue
        # filter image retina suffixes like logo@2x.png, logo@3x.webp
        if re.search(r"@\d+x\.(png|jpg|jpeg|webp|gif|svg)", e, re.I): continue
        if domain_filter and not e.endswith(f"@{domain_filter}"): continue
        clean.append(e)
    return clean


# ── Attacks ────────────────────────────────────────────────────────────────────

def attack_dmarc(domain):
    """DNS: _dmarc TXT rua/ruf mailto. Fast (~0.05s), ~10% hit rate."""
    for txt in dns_txt(f"_dmarc.{domain}"):
        for part in txt.split(";"):
            part = part.strip().strip('"')
            if part.lower().startswith(("rua=", "ruf=")):
                for e in re.findall(r"mailto:([^\s,>]+)", part, re.I):
                    e = e.strip().lower()
                    elocal  = e.split("@")[0] if "@" in e else ""
                    edomain = e.split("@")[1] if "@" in e else ""
                    if (is_valid_email(e)
                            and not any(e.endswith(s) for s in DENY_SUFFIXES)
                            and not any(edomain == d or edomain.endswith("."+d)
                                        for d in DENY_DMARC_DOMAINS)
                            and elocal not in DENY_DMARC_LOCALS):
                        return e, "dmarc"
    return None, None

def attack_schema(domain):
    """
    HTTP: Schema.org JSON-LD + Cloudflare decode + mailto links.
    Homepage + Shopify sub-pages fetched in parallel (was sequential).
    Timeout reduced 6->3s.
    """
    urls = [f"https://{domain}"] + [f"https://{domain}{p}" for p in SHOPIFY_PAGES]

    def fetch(url):
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=(HTTP_CONNECT_TO, HTTP_READ_TO),
                             allow_redirects=True)
            if r.status_code == 200:
                return url, r.text  # no cap here — lean_html strips scripts first, reducing 900KB -> ~70KB
        except Exception:
            pass
        return url, None

    pages = {}
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        futures = {pool.submit(fetch, u): u for u in urls}
        for fut in as_completed(futures):
            url, html = fut.result()
            if html:
                pages[url] = html

    def lean_html(raw_html):
        """
        Strip script/style tags (bulk of Shopify page weight) and return
        both the soup and a stripped HTML string for regex scanning.
        Avoids 300K cap cutting off emails buried in large pages.
        """
        soup = BeautifulSoup(raw_html, "html.parser")
        for tag in soup.find_all(["script", "style", "link", "noscript"]):
            tag.decompose()
        return soup, str(soup)

    # Homepage: JSON-LD first (must run before stripping scripts)
    homepage_html = pages.get(f"https://{domain}", "")
    if homepage_html:
        raw_soup = BeautifulSoup(homepage_html, "html.parser")
        for tag in raw_soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(tag.string or "")
                items = data if isinstance(data, list) else [data]
                for item in items:
                    e = item.get("email") or ""
                    if not e and isinstance(item.get("contactPoint"), dict):
                        e = item["contactPoint"].get("email", "")
                    if e:
                        e = e.strip().lower().lstrip("mailto:")
                        if is_valid_email(e) and not any(e.endswith(s) for s in DENY_SUFFIXES):
                            return e, "jsonld"
            except Exception:
                pass

    # All pages: strip scripts/styles, then scan lean HTML
    for url, html in pages.items():
        page_key = url.split("/")[-1] or "homepage"
        soup, lean = lean_html(html)
        # Footer is the most reliable spot for contact info
        footer = soup.find("footer")
        if footer:
            for e in scrape_emails_from_html(str(footer)):
                return e, f"footer_{page_key}"
        # Full lean page (scripts stripped — much smaller than raw)
        for e in scrape_emails_from_html(lean):
            return e, f"scrape_{page_key}"

    return None, None


def attack_whois(domain):
    """
    WHOIS: registrant/admin email. Fast if not privacy-protected.
    Hit rate low (most use privacy guard) but when it works, it's direct owner email.
    """
    if not HAS_WHOIS:
        raise Exception("python-whois not installed")
    # Domains used by registrar privacy/proxy services — never a real store contact
    WHOIS_PROXY_DOMAINS = {
        "registrar.shopify.com", "wix-domains.com", "godaddy.com", "namecheap.com",
        "domains.google.com", "key-systems.net", "registrar-servers.com",
        "networksolutions.com", "tucows.com", "enom.com", "name.com",
        "squarespace.com", "hover.com", "cloudflare.com", "iwantmyname.com",
        "fastly.net", "above.com", "domainsbyproxy.com", "privacyguardian.org",
        "whoisguard.com", "privateregistration.com", "contactprivacy.com",
        "internet.bs", "dynadot.com", "porkbun.com",
    }
    w = whois_lib.whois(domain)
    emails = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
    for e in emails:
        if not e: continue
        e = e.lower().strip()
        edomain = e.split("@")[1] if "@" in e else ""
        if (is_valid_email(e)
                and not any(e.endswith(s) for s in DENY_SUFFIXES)
                and edomain not in WHOIS_PROXY_DOMAINS
                and "privacy" not in e
                and "proxy" not in e
                and "protect" not in e
                and "abuse" not in e.split("@")[0]
                and "noreply" not in e.split("@")[0]
                and "no-reply" not in e.split("@")[0]):
            return e, "whois"
    return None, None

def attack_smtp(domain):
    """
    MX + SMTP RCPT-TO role guessing.
    Iteration 2: timeout 5->2s, ports [25,587] only, single connection per port.
    """
    mx = dns_mx(domain)
    if not mx:
        raise Exception("no MX record")

    for port in SMTP_PORTS:
        try:
            if port == 465:
                ctx = ssl.create_default_context()
                smtp = smtplib.SMTP_SSL(mx, 465, timeout=SMTP_TO, context=ctx)
            else:
                smtp = smtplib.SMTP(mx, port, timeout=SMTP_TO)
                if port == 587:
                    smtp.starttls()
            with smtp:
                smtp.ehlo("outreach.probe.xyz")
                smtp.mail("probe@outreach.probe.xyz")
                # catch-all probe
                code, _ = smtp.rcpt(f"{CATCHALL_PROBE}@{domain}")
                if code == 250:
                    return f"{ROLE_GUESSES[0]}@{domain}", f"catchall_port{port}"
                # role guesses in single connection
                for local in ROLE_GUESSES:
                    email = f"{local}@{domain}"
                    code, _ = smtp.rcpt(email)
                    if code == 250:
                        return email, f"smtp_verified_port{port}"
            return None, None  # connected, no hit
        except smtplib.SMTPConnectError:
            continue
        except smtplib.SMTPServerDisconnected:
            continue
        except Exception:
            continue

    raise Exception(f"SMTP blocked on all ports (mx={mx})")


def attack_google_dork(domain):
    """
    Google search via Serper API for '@domain' pattern.
    Finds emails indexed on press, directories, social bios, Etsy, etc. —
    pages we'd never think to scrape directly.

    Dorks tried in order (most → least specific):
      1. "@domain.com" -site:domain.com   — email on OTHER sites mentioning this domain
      2. "@domain.com"                    — anywhere Google has indexed it
      3. contact OR email site:domain.com — surfaces contact pages Google knows about

    Requires SERPER_API_KEY env var (serper.dev, $1/1k queries).
    """
    import os
    api_key = os.environ.get("SERPER_API_KEY", "")
    if not api_key:
        raise Exception("SERPER_API_KEY not set")

    headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
    dorks = [
        f'"@{domain}" -site:{domain}',
        f'"@{domain}"',
        f'contact OR email site:{domain}',
    ]

    for dork in dorks:
        try:
            r = requests.post(
                "https://google.serper.dev/search",
                headers=headers,
                json={"q": dork, "num": 10},
                timeout=10,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            # Search organic results + knowledge graph + answer box
            texts = []
            for item in data.get("organic", []):
                texts.append(item.get("snippet", "") + " " + item.get("title", ""))
            texts.append(data.get("answerBox", {}).get("answer", ""))
            texts.append(data.get("answerBox", {}).get("snippet", ""))

            for text in texts:
                for e in EMAIL_RE.findall(text):
                    e = e.lower().strip().rstrip(".")
                    if (is_valid_email(e)
                            and not any(e.endswith(s) for s in DENY_SUFFIXES)
                            and not re.search(r"@\d+x\.(png|jpg|jpeg|webp|gif|svg)", e, re.I)):
                        return e, f"dork:{dork[:40]}"
        except Exception:
            continue

    return None, None


def attack_contact_url(domain, contact_url=None, about_url=None):
    """
    Fetch DB-provided contact/about URLs from StoreLeads (contactPageUrl / aboutUsUrl).
    Only tries URLs explicitly stored in the DB — slug guessing is handled by schema.
    Fast when DB has non-standard paths (e.g. /policies/contact-information).
    """
    urls_to_try = [u for u in [contact_url, about_url] if u]
    if not urls_to_try:
        return None, None

    def fetch_and_scan(url):
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=(HTTP_CONNECT_TO, HTTP_READ_TO),
                             allow_redirects=True)
            if r.status_code != 200:
                return None, None
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["script", "style", "link", "noscript"]):
                tag.decompose()
            emails = scrape_emails_from_html(str(soup))
            if emails:
                return emails[0], url
        except Exception:
            pass
        return None, None

    # Fire all URLs in parallel. Return as soon as the first email is found,
    # preserving priority order (DB URL > /policies/contact-information > slugs).
    # On a hit: shutdown pool without waiting — remaining requests run to their
    # own timeout in background but we don't block on them.
    # On a miss: as_completed drains naturally at ~max(individual timeouts).
    pool = ThreadPoolExecutor(max_workers=len(urls_to_try))
    future_to_url = {pool.submit(fetch_and_scan, u): u for u in urls_to_try}
    results = {}
    try:
        for fut in as_completed(future_to_url):
            url = future_to_url[fut]
            email, src = fut.result()
            results[url] = (email, src)
            if email:
                pool.shutdown(wait=False)
                break
    except Exception:
        pass

    for url in urls_to_try:
        email, src = results.get(url, (None, None))
        if email:
            return email, f"contact_url:{src}"

    return None, None


# ── Per-domain runner ──────────────────────────────────────────────────────────

# Known contact/about URLs from StoreLeads DB (contactPageUrl / aboutUsUrl columns)
KNOWN_URLS = {
    "thecaliforniacandleco.com": {
        "contact": "https://www.thecaliforniacandleco.com/policies/contact-information",
        "about":   "https://www.thecaliforniacandleco.com/pages/about",
    },
    "heretoy.com": {
        "contact": "https://www.heretoy.com/pages/contact",
        "about":   "https://www.heretoy.com/pages/about-us",
    },
    "molten.world":   {"contact": "https://molten.world/pages/contact"},
    "tagliariol.shop": {"contact": "https://tagliariol.shop/pages/contact"},
}

ATTACKS = {
    "dmarc":       attack_dmarc,
    "contact_url": lambda d: attack_contact_url(
                       d,
                       contact_url=KNOWN_URLS.get(d, {}).get("contact"),
                       about_url=KNOWN_URLS.get(d, {}).get("about"),
                   ),
    "schema":      attack_schema,
    "smtp":        attack_smtp,
    "google_dork": attack_google_dork,
}

def run_domain(domain, enabled_attacks):
    results = {}
    for name in enabled_attacks:
        fn = ATTACKS[name]
        t0 = time.perf_counter()
        try:
            raw = fn(domain)
            elapsed = time.perf_counter() - t0
            email, sub = raw if isinstance(raw, tuple) else (raw, None)
            if email:
                log(domain, name, f"FOUND {email!r}  sub={sub}  ({elapsed:.2f}s)")
                results[name] = {"email": email, "sub": sub, "time": round(elapsed, 3), "status": "found"}
            else:
                log(domain, name, f"empty  ({elapsed:.2f}s)")
                results[name] = {"email": None, "time": round(elapsed, 3), "status": "empty"}
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            kind = "timeout" if "timed out" in str(exc).lower() or "timeout" in str(exc).lower() else "error"
            log(domain, name, f"{kind.upper()}  {exc}  ({elapsed:.2f}s)")
            results[name] = {"email": None, "time": round(elapsed, 3), "status": kind, "reason": str(exc)}
    return domain, results


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(all_results, enabled_attacks):
    print("\n" + "="*80)
    print("SUMMARY — WITH GOOGLE DORKS + CONTACT URL")
    print("="*80)

    print(f"\n{'Attack':<14} {'Found':>6} {'Empty':>6} {'Timeout':>8} {'Error':>6} {'Avg(s)':>7} {'Max(s)':>7}")
    print("-"*60)
    for atk in enabled_attacks:
        rows = [r[atk] for r in all_results.values() if atk in r]
        if not rows: continue
        found   = sum(1 for r in rows if r["status"] == "found")
        empty   = sum(1 for r in rows if r["status"] == "empty")
        timeout = sum(1 for r in rows if r["status"] == "timeout")
        error   = sum(1 for r in rows if r["status"] == "error")
        times   = [r["time"] for r in rows]
        avg_t   = sum(times) / len(times) if times else 0
        max_t   = max(times) if times else 0
        print(f"{atk:<14} {found:>6} {empty:>6} {timeout:>8} {error:>6} {avg_t:>7.2f} {max_t:>7.2f}")

    print(f"\n{'Domain':<35} {'Best email':<38} {'Attack':<16} {'Sub'}")
    print("-"*100)
    for domain, res in all_results.items():
        found = [(atk, r) for atk, r in res.items() if r["status"] == "found"]
        if found:
            atk, r = found[0]
            print(f"{domain:<35} {r['email']:<38} {atk:<16} {r.get('sub') or ''}")
        else:
            statuses = {atk: r["status"] for atk, r in res.items()}
            print(f"{domain:<35} {'-- no result --':<38} {str(statuses)}")

    total = len(all_results)
    hits  = sum(1 for res in all_results.values()
                if any(r["status"] == "found" for r in res.values()))
    print(f"\nOverall hit rate: {hits}/{total} ({hits/total*100:.0f}%)")

    out = Path(__file__).parent / "experiment_results_dorks.json"
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Full results -> {out}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=WORKERS)
    ap.add_argument("--attack",  help="comma-separated subset, e.g. dmarc,schema")
    args = ap.parse_args()

    enabled = args.attack.split(",") if args.attack else list(ATTACKS.keys())
    unknown = [a for a in enabled if a not in ATTACKS]
    if unknown:
        print(f"Unknown attacks: {unknown}. Available: {list(ATTACKS.keys())}")
        return

    print(f"Domains   : {len(DOMAINS)}")
    print(f"Attacks   : {enabled}")
    print(f"Workers   : {args.workers}")
    print(f"Timeouts  : HTTP=({HTTP_CONNECT_TO},{HTTP_READ_TO})s  SMTP={SMTP_TO}s  DNS={DNS_TO}s")
    print("="*80 + "\n")

    all_results = {}
    t_total = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_domain, d, enabled): d for d in DOMAINS}
        for fut in as_completed(futures):
            domain, res = fut.result()
            all_results[domain] = res

    elapsed_total = time.perf_counter() - t_total
    print(f"\nTotal wall time: {elapsed_total:.1f}s")
    print_summary(all_results, enabled)

if __name__ == "__main__":
    main()
