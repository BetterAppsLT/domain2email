#!/usr/bin/env python3
"""
l33t email finder for Shopify stores.

Attack surface (in order of reliability):
  1. DMARC record  — _dmarc.domain rua/ruf often has a real admin email
  2. Schema.org JSON-LD — Shopify themes embed Organization/LocalBusiness with email
  3. SPF record — reveals email provider (GSuite → first@, Zoho → info@, etc.)
  4. SMTP RCPT TO — role-guess verification on ports 25/587/465
  5. crt.sh subdomains — discovers mail.*, admin.*, etc.
  6. DDG search — queries "@domain.com" to surface publicly indexed emails
  7. Unverified best-guess — fallback when all verification fails

Usage:
  python src/smtp_finder.py --input out/outreach_stores_enriched.csv [--limit N] [--workers N]
  python src/smtp_finder.py --domain example.com
  python src/smtp_finder.py --stats
"""

import argparse, csv, json, re, smtplib, socket, ssl, threading, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("Warning: pip install dnspython for MX/SPF/DMARC lookups")

ROOT       = Path(__file__).resolve().parent.parent
HTTP_TO    = 6
SMTP_TO    = 5
DNS_TO     = 4
WORKERS    = 10
SMTP_PORTS = [25, 587, 465]
UA         = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36")
CATCHALL_PROBE = "zz-no-exist-xq7r-probe"
EMAIL_RE   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

ROLE_GUESSES = [
    "info", "support", "hello", "contact", "sales",
    "shop", "team", "care", "help", "admin",
    "orders", "customerservice", "service", "hi",
    "store", "mail", "office", "enquiries", "enquiry",
    "hola", "contacto", "bonjour",
]

FREE_MAIL = {"gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com",
             "protonmail.com","proton.me","zoho.com","aol.com"}

DENY_SUFFIXES = (
    "@sentry.io","@example.com","@yourdomain.com","@domain.com",
    "@shopify.com","@myshopify.com","@klaviyo.com","@sendgrid.net",
    "@googletagmanager.com","@google-analytics.com",
    "@gitbook.io","@gitbook.com","@notion.so","@typeform.com",
)

# DMARC reporting service domains — rua/ruf point here, not real store inboxes
DENY_DMARC_DOMAINS = {
    "mailhardener.com", "dmarcian.com", "dmarc.postmarkapp.com",
    "agari.com", "valimail.com", "easydmarc.com", "uriports.com",
    "mxtoolbox.com", "dmarcanalyzer.com", "dmarcreport.com",
    "postmark.com", "proofpoint.com", "redsift.io",
    "reportdmarc.nl", "onsecureserver.net", "brevo.com",
    "robot.simply.com", "usecart.com",
}

# Local parts that are system/monitoring addresses — never real store contacts
DENY_DMARC_LOCALS = {
    "abuse", "postmaster", "noreply", "no-reply", "mailer-daemon",
    "hostmaster", "webmaster", "dmarc", "dmarc-reports", "dmarc_rua",
    "dmarc_ruf", "rua", "ruf", "bounces", "bounce",
}

VALID_TLDS = {
    "com","net","org","io","co","me","store","shop","uk","us","au","de","fr",
    "nl","se","no","dk","fi","be","at","ch","es","it","pt","ca","nz","ie",
    "online","tech","digital","app","dev","ai","studio","agency","media",
    "health","care","life","art","email","club","site","link","social",
    "photography","consulting","solutions","software","global","group",
    "clothing","jewelry","beauty","fitness","coffee","garden","pet","food",
    # country codes
    "ac","ad","ae","af","ag","al","am","ao","ar","as","aw","az","ba","bb",
    "bd","bf","bg","bh","bi","bj","bm","bn","bo","br","bs","bt","bw","by",
    "bz","cc","cd","cf","cg","ci","ck","cl","cm","cn","cr","cu","cv","cw",
    "cx","cy","cz","dj","dk","dm","do","dz","ec","ee","eg","er","et","eu",
    "fj","fk","fm","fo","ga","gb","gd","ge","gg","gh","gi","gl","gm","gn",
    "gp","gq","gr","gt","gu","gw","gy","hk","hn","hr","ht","hu","id","il",
    "im","in","iq","ir","is","je","jm","jo","jp","ke","kg","kh","ki","km",
    "kn","kp","kr","kw","ky","kz","la","lb","lc","li","lk","lr","ls","lt",
    "lu","lv","ly","ma","mc","md","mg","mh","mk","ml","mm","mn","mo","mp",
    "mq","mr","ms","mt","mu","mv","mw","mx","my","mz","na","nc","ne","nf",
    "ng","ni","np","nr","nu","om","pa","pe","pf","pg","ph","pk","pl","pm",
    "pn","pr","ps","pt","pw","py","qa","re","ro","rs","ru","rw","sa","sb",
    "sc","sd","sg","sh","si","sk","sl","sm","sn","so","sr","ss","st","su",
    "sv","sx","sy","sz","tc","td","tf","tg","th","tj","tk","tl","tm","tn",
    "to","tr","tt","tv","tw","tz","ua","ug","uy","uz","va","vc","ve","vg",
    "vi","vn","vu","wf","ws","ye","yt","za","zm","zw",
}


def log(msg): print(msg, flush=True)


# ── DNS helpers ────────────────────────────────────────────────────────────────
def dns_txt(name):
    if not HAS_DNS: return []
    try:
        return [str(r) for r in dns.resolver.resolve(name, "TXT", lifetime=DNS_TO)]
    except Exception: return []

def dns_mx(domain):
    if not HAS_DNS: return None
    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=DNS_TO)
        best = min(records, key=lambda r: r.preference)
        mx = str(best.exchange).rstrip(".")
        # Walk up to apex if subdomain
        if not mx: raise Exception()
        return mx
    except Exception:
        try:
            parts = domain.split(".")
            if len(parts) > 2:
                apex = ".".join(parts[-2:])
                records = dns.resolver.resolve(apex, "MX", lifetime=DNS_TO)
                best = min(records, key=lambda r: r.preference)
                return str(best.exchange).rstrip(".")
        except Exception: pass
    return None


# ── Cloudflare email protection decoder ──────────────────────────────────────
def decode_cloudflare_email(encoded):
    key = int(encoded[:2], 16)
    return "".join(chr(int(encoded[i:i+2], 16) ^ key) for i in range(2, len(encoded), 2))

def extract_cloudflare_emails(html):
    """Find all Cloudflare-protected emails in raw HTML."""
    found = []
    for encoded in re.findall(r'data-cfemail="([0-9a-f]+)"', html, re.I):
        try:
            e = decode_cloudflare_email(encoded).lower()
            if is_valid_email(e):
                found.append(e)
        except Exception:
            pass
    return found


# ── Attack 1: DMARC record ────────────────────────────────────────────────────
def extract_dmarc_email(domain):
    """
    _dmarc.domain TXT record often contains rua=mailto:dmarc@domain.com
    This is a real monitored inbox — usually IT/admin.
    """
    for txt in dns_txt(f"_dmarc.{domain}"):
        for part in txt.split(";"):
            part = part.strip().strip('"')
            if part.lower().startswith(("rua=", "ruf=")):
                emails = re.findall(r"mailto:([^\s,>]+)", part, re.I)
                for e in emails:
                    e = e.strip().lower()
                    elocal  = e.split("@")[0] if "@" in e else ""
                    edomain = e.split("@")[1] if "@" in e else ""
                    if is_valid_email(e) \
                            and not any(e.endswith(s) for s in DENY_SUFFIXES) \
                            and not any(edomain == d or edomain.endswith("."+d) for d in DENY_DMARC_DOMAINS) \
                            and elocal not in DENY_DMARC_LOCALS:
                        return e, "dmarc_record"
    return None, None


# ── Attack 1b: TLS-RPT record ─────────────────────────────────────────────────
def extract_tlsrpt_email(domain):
    """
    _smtp._tls.domain TXT (RFC 8460) contains rua=mailto: pointing to a real admin inbox.
    Separate from DMARC, rarely queried by other tools.
    """
    for txt in dns_txt(f"_smtp._tls.{domain}"):
        emails = re.findall(r"mailto:([^\s,>]+)", txt, re.I)
        for e in emails:
            e = e.strip().lower()
            elocal  = e.split("@")[0] if "@" in e else ""
            edomain = e.split("@")[1] if "@" in e else ""
            if is_valid_email(e) \
                    and not any(e.endswith(s) for s in DENY_SUFFIXES) \
                    and edomain not in DENY_DMARC_DOMAINS \
                    and elocal not in DENY_DMARC_LOCALS:
                return e, "tlsrpt_record"
    return None, None


# ── Attack 2: Schema.org JSON-LD + Cloudflare decode ─────────────────────────
def extract_schema_email(domain):
    """
    Many Shopify themes embed Organization/LocalBusiness JSON-LD with email field.
    """
    try:
        r = requests.get(f"https://{domain}", headers={"User-Agent": UA},
                         timeout=HTTP_TO, allow_redirects=True)
        if r.status_code != 200: return None, None
        html = r.text[:300_000]
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(tag.string or "")
                items = data if isinstance(data, list) else [data]
                for item in items:
                    e = (item.get("email") or "")
                    if not e and isinstance(item.get("contactPoint"), dict):
                        e = item["contactPoint"].get("email","")
                    if e:
                        e = e.strip().lower().lstrip("mailto:")
                        if "'" in e or "{" in e or "%" in e:
                            continue  # template artifact e.g. support'@'tenereteam.com
                        if is_valid_email(e) and not any(e.endswith(s) for s in DENY_SUFFIXES):
                            return e, "schema_jsonld"
            except Exception: pass
        # Cloudflare email protection decode
        for e in extract_cloudflare_emails(html):
            if not any(e.endswith(s) for s in DENY_SUFFIXES):
                return e, "cloudflare_decode"

        # Meta tags
        for tag in soup.find_all("meta"):
            content = tag.get("content","")
            if EMAIL_RE.search(content):
                for e in EMAIL_RE.findall(content):
                    e = e.lower()
                    if is_valid_email(e) and not any(e.endswith(s) for s in DENY_SUFFIXES):
                        return e, "meta_tag"

        # Shopify contact/about pages
        for path in ["/pages/contact", "/pages/contact-us", "/pages/about",
                     "/pages/about-us", "/pages/team"]:
            try:
                pr = requests.get(f"https://{domain}{path}", headers={"User-Agent": UA},
                                  timeout=HTTP_TO, allow_redirects=True)
                if pr.status_code != 200: continue
                page_html = pr.text[:300_000]
                for e in extract_cloudflare_emails(page_html):
                    if not any(e.endswith(s) for s in DENY_SUFFIXES):
                        return e, "cloudflare_decode"
                for e in EMAIL_RE.findall(page_html):
                    e = e.lower()
                    if is_valid_email(e) and not any(e.endswith(s) for s in DENY_SUFFIXES) \
                            and "'" not in e and "{" not in e:
                        return e, "page_scrape"
            except Exception: pass
    except Exception: pass
    return None, None


# ── Attack 2b: Wayback Machine ────────────────────────────────────────────────
def wayback_find_email(domain):
    """
    Query Wayback CDX API for historical contact/about page snapshots.
    Recovers emails merchants exposed pre-Cloudflare, now hidden behind contact forms.
    """
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/pages/contact*&output=json&fl=timestamp,original"
            f"&filter=statuscode:200&limit=5&collapse=urlkey"
        )
        r = requests.get(cdx_url, timeout=HTTP_TO, headers={"User-Agent": UA})
        if r.status_code != 200: return None, None
        rows = r.json()
        if len(rows) <= 1: return None, None  # first row is header
        for ts, orig_url in rows[1:]:
            snap_url = f"https://web.archive.org/web/{ts}/{orig_url}"
            try:
                sr = requests.get(snap_url, headers={"User-Agent": UA},
                                  timeout=HTTP_TO, allow_redirects=True)
                html = sr.text[:300_000]
                for e in extract_cloudflare_emails(html):
                    if not any(e.endswith(s) for s in DENY_SUFFIXES):
                        return e, "wayback_cloudflare"
                for e in EMAIL_RE.findall(html):
                    e = e.lower()
                    if is_valid_email(e) and e.endswith(f"@{domain}") \
                            and not any(e.endswith(s) for s in DENY_SUFFIXES) \
                            and "'" not in e:
                        return e, "wayback_scrape"
            except Exception: pass
    except Exception: pass
    return None, None


# ── Attack 3: SPF → provider hint ────────────────────────────────────────────
def detect_email_provider(domain):
    """
    SPF record reveals which email service the domain uses.
    Helps prioritize guesses: GSuite → first name patterns; Zoho → info/contact.
    Returns: 'google', 'zoho', 'microsoft', 'protonmail', 'generic'
    """
    for txt in dns_txt(domain):
        low = txt.lower()
        if "google" in low or "googlemail" in low or "_spf.google.com" in low:
            return "google"
        if "zoho" in low:
            return "zoho"
        if "protection.outlook.com" in low or "microsoft" in low:
            return "microsoft"
        if "protonmail" in low:
            return "protonmail"
        if "mailgun" in low or "sendgrid" in low:
            return "transactional_only"  # probably no real inbox
    return "generic"


def provider_guesses(provider):
    """Extra guesses based on detected provider."""
    if provider == "google":
        # Google Workspace — owners often use their name
        return ["hello", "info", "contact", "support"]
    if provider == "zoho":
        return ["info", "contact", "sales", "hello"]
    if provider == "microsoft":
        return ["info", "contact", "support", "admin"]
    return []


# ── Attack 4: crt.sh subdomains ───────────────────────────────────────────────
def crtsh_subdomains(domain):
    """
    Certificate transparency logs reveal subdomains.
    mail.*, webmail.*, smtp.* hint at self-hosted mail → try SMTP there too.
    """
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         timeout=HTTP_TO, headers={"User-Agent": UA})
        if r.status_code != 200: return []
        names = set()
        for entry in r.json():
            name = entry.get("name_value","").lower()
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    names.add(sub)
        return list(names)
    except Exception: return []


def find_mail_subdomain(domain):
    """Check if mail.*/webmail.*/smtp.* subdomain exists — hints at self-hosted MX."""
    for prefix in ["mail","webmail","smtp","mx","email"]:
        sub = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(sub, None, timeout=2)
            return sub
        except Exception: pass
    return None


# ── Attack 5: DDG search for public email ────────────────────────────────────
def ddg_find_email(domain):
    """
    Search DDG for "@domain.com" — surfaces emails publicly indexed on social,
    directories, about pages, etc.
    """
    try:
        from ddgs import DDGS
        query = f'"@{domain}"'
        results = DDGS().text(query, max_results=5)
        for r in (results or []):
            text = (r.get("body","") or "") + " " + (r.get("title","") or "")
            for e in EMAIL_RE.findall(text):
                e = e.lower()
                if e.endswith(f"@{domain}") and is_valid_email(e) \
                        and not any(e.endswith(s) for s in DENY_SUFFIXES):
                    return e, "ddg_search"
    except Exception: pass
    return None, None


# ── Attack 6: SMTP verification ───────────────────────────────────────────────
def smtp_verify(email, mx_host, port=25, helo="outreach.probe.xyz"):
    """
    Returns: 'exists' | 'not_exist' | 'catchall' | 'error'
    Tries plain SMTP on port 25, STARTTLS on 587, SMTPS on 465.
    """
    domain = email.split("@")[1]
    probe  = f"{CATCHALL_PROBE}@{domain}"
    try:
        if port == 465:
            ctx = ssl.create_default_context()
            smtp = smtplib.SMTP_SSL(mx_host, 465, timeout=SMTP_TO, context=ctx)
        else:
            smtp = smtplib.SMTP(mx_host, port, timeout=SMTP_TO)
            if port == 587:
                smtp.starttls()
        with smtp:
            smtp.ehlo(helo)
            smtp.mail(f"probe@{helo}")
            code, _ = smtp.rcpt(probe)
            if code == 250:
                return "catchall"
            code, _ = smtp.rcpt(email)
            return "exists" if code == 250 else "not_exist"
    except Exception:
        return "error"

def smtp_check_all_ports(email, mx_host):
    for port in SMTP_PORTS:
        result = smtp_verify(email, mx_host, port)
        if result != "error":
            return result
    return "error"


# ── Email validation ───────────────────────────────────────────────────────────
def is_valid_email(e):
    if not e or e.count("@") != 1: return False
    local, dom = e.split("@",1)
    if not (3 <= len(local) <= 64): return False
    if not dom or "." not in dom: return False
    tld = dom.rsplit(".",1)[-1].lower()
    if tld not in VALID_TLDS: return False
    if len(local) >= 12 and "." not in local and "_" not in local and "-" not in local \
            and any(c.isdigit() for c in local) and any(c.isalpha() for c in local):
        return False
    return True


# ── Master finder ──────────────────────────────────────────────────────────────
def find_email(domain, learned_guesses=None):
    result = {
        "domain": domain, "email": None, "method": None,
        "catchall": False, "mx": None, "provider": None,
        "smtp_port": None, "tried_attacks": [], "verified_at": None,
    }
    if not domain or domain in FREE_MAIL:
        result["method"] = "skipped"; return result

    # ── 1. DMARC ──
    result["tried_attacks"].append("dmarc")
    e, method = extract_dmarc_email(domain)
    if e:
        result.update(email=e, method=method, verified_at=_now()); return result

    # ── 1b. TLS-RPT ──
    result["tried_attacks"].append("tlsrpt")
    e, method = extract_tlsrpt_email(domain)
    if e:
        result.update(email=e, method=method, verified_at=_now()); return result

    # ── 2. Schema.org + Cloudflare decode + Shopify pages ──
    result["tried_attacks"].append("schema")
    e, method = extract_schema_email(domain)
    if e:
        result.update(email=e, method=method, verified_at=_now()); return result

    # ── 2b. Wayback Machine ──
    result["tried_attacks"].append("wayback")
    e, method = wayback_find_email(domain)
    if e:
        result.update(email=e, method=method, verified_at=_now()); return result

    # ── 3. SPF provider detection ──
    result["tried_attacks"].append("spf")
    provider = detect_email_provider(domain)
    result["provider"] = provider
    if provider == "transactional_only":
        result["method"] = "transactional_only"; return result

    # ── 4. DDG public email search ──
    result["tried_attacks"].append("ddg")
    e, method = ddg_find_email(domain)
    if e:
        result.update(email=e, method=method, verified_at=_now()); return result

    # ── 5. MX lookup + SMTP verification ──
    result["tried_attacks"].append("smtp")
    mx = dns_mx(domain)
    result["mx"] = mx
    if mx:
        guesses = list(dict.fromkeys(
            provider_guesses(provider) +
            (learned_guesses or []) +
            ROLE_GUESSES
        ))
        for local in guesses:
            email = f"{local}@{domain}"
            status = smtp_check_all_ports(email, mx)
            if status == "catchall":
                result.update(email=f"{guesses[0]}@{domain}", method="catchall_guess",
                               catchall=True, verified_at=_now())
                return result
            elif status == "exists":
                result.update(email=email, method="smtp_verified", verified_at=_now())
                return result
            elif status == "error":
                # SMTP blocked — fall through to unverified guess
                break

    # ── 6. crt.sh + mail subdomain check ──
    result["tried_attacks"].append("crtsh")
    mail_sub = find_mail_subdomain(domain)
    if mail_sub and mx:
        # Try SMTP on discovered subdomain as alt MX
        for local in (learned_guesses or [])[:5] + ROLE_GUESSES[:5]:
            email = f"{local}@{domain}"
            status = smtp_check_all_ports(email, mail_sub)
            if status == "exists":
                result.update(email=email, method="smtp_verified_sub", verified_at=_now())
                return result

    # ── 7. Unverified best-guess fallback ──
    if mx or mail_sub:
        guesses = list(dict.fromkeys((learned_guesses or []) + ROLE_GUESSES))
        result.update(email=f"{guesses[0]}@{domain}", method="unverified_guess",
                      verified_at=_now())

    return result

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Load learned patterns ──────────────────────────────────────────────────────
def load_learned_guesses():
    counts = Counter()
    for fname in ["out/ppu_stores_enriched.csv", "out/outreach_stores_enriched.csv"]:
        p = ROOT / fname
        if not p.exists(): continue
        for row in csv.DictReader(open(p)):
            e = (row.get("email") or "").strip().lower()
            if e and "@" in e:
                local = e.split("@")[0]
                if re.match(r"^[a-z0-9._+-]{2,30}$", local):
                    counts[local] += 1
    return [local for local, _ in counts.most_common()]


# ── Batch enrichment ───────────────────────────────────────────────────────────
def run_enrichment(input_path, limit, workers):
    input_path = Path(input_path)
    rows = list(csv.DictReader(open(input_path)))
    learned = load_learned_guesses()
    merged  = list(dict.fromkeys(learned + ROLE_GUESSES))
    log(f"Learned patterns (top 8): {merged[:8]}")
    log(f"Total learned: {len(learned)}\n")

    targets = [r for r in rows
               if r.get("domain")
               and not r.get("email")
               and float(r.get("confidence") or 0) >= 0.5
               and r.get("domain") not in FREE_MAIL]
    if limit: targets = targets[:limit]
    log(f"Targets (domain, no email, conf>=0.5): {len(targets)}\n")

    smtp_results = {}
    stats = Counter()
    lock  = threading.Lock()
    done  = 0

    def process(r):
        return find_email(r["domain"], extra_guesses=merged)

    # Patch find_email signature for extra_guesses
    import functools
    def _process(r):
        return find_email(r["domain"], learned_guesses=merged)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_process, r): r for r in targets}
            for fut in as_completed(futures):
                res = fut.result()
                r   = futures[fut]
                with lock:
                    smtp_results[res["domain"]] = res
                    done += 1
                    stats[res["method"] or "none"] += 1
                    e_str    = res["email"] or "—"
                    catchall = " [catch-all]" if res["catchall"] else ""
                    attacks  = ",".join(res.get("tried_attacks",[]))
                    log(f"  [{done}/{len(targets)}] {r.get('store_name',r['domain'])} "
                        f"→ {e_str}{catchall}  [{res['method']}]  via:{attacks}")
    except KeyboardInterrupt:
        log("\n[interrupted]")

    # Write output
    out_path = input_path.parent / (input_path.stem + "_smtp.csv")
    fieldnames = list(rows[0].keys())
    for col in ["smtp_email","smtp_method","smtp_catchall","smtp_mx","smtp_provider"]:
        if col not in fieldnames: fieldnames.append(col)

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            res = smtp_results.get(r.get("domain",""))
            if res:
                r["smtp_email"]    = res["email"] or ""
                r["smtp_method"]   = res["method"] or ""
                r["smtp_catchall"] = "yes" if res["catchall"] else ""
                r["smtp_mx"]       = res["mx"] or ""
                r["smtp_provider"] = res["provider"] or ""
                if not r.get("email") and res["email"] and res["method"] in ("smtp_verified","dmarc_record","schema_jsonld","ddg_search"):
                    r["email"] = res["email"]
            w.writerow(r)

    log(f"\nWritten → {out_path.name}")
    total = len(targets)
    log("Method breakdown:")
    for method, n in stats.most_common():
        log(f"  {method}: {n} ({n/max(total,1)*100:.1f}%)")


# ── Single domain test ─────────────────────────────────────────────────────────
def test_domain(domain):
    learned = load_learned_guesses()
    merged  = list(dict.fromkeys(learned + ROLE_GUESSES))
    log(f"Testing {domain}…")
    res = find_email(domain, learned_guesses=merged)
    log(json.dumps({k: v for k, v in res.items() if k != "tried_attacks"}, indent=2))
    log(f"Attacks tried: {res['tried_attacks']}")


def show_stats():
    learned = load_learned_guesses()
    counts  = Counter()
    for fname in ["out/ppu_stores_enriched.csv","out/outreach_stores_enriched.csv"]:
        p = ROOT / fname
        if not p.exists(): continue
        for row in csv.DictReader(open(p)):
            e = (row.get("email") or "").strip().lower()
            if e and "@" in e: counts[e.split("@")[0]] += 1
    log(f"Top email local-parts ({len(counts)} unique):")
    for local, n in counts.most_common(25):
        print(f"  {n:3d}  {local}")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",   help="Enriched CSV to process")
    ap.add_argument("--domain",  help="Test a single domain")
    ap.add_argument("--stats",   action="store_true")
    ap.add_argument("--limit",   type=int, default=None)
    ap.add_argument("--workers", type=int, default=WORKERS)
    args = ap.parse_args()

    if args.stats:   show_stats(); return
    if args.domain:  test_domain(args.domain); return
    if args.input:   run_enrichment(args.input, args.limit, args.workers); return
    ap.print_help()

if __name__ == "__main__":
    main()
