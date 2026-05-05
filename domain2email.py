#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
domain2email.py — production email enricher for Shopify store domains.

Finds the founder/owner email for a domain using layered attacks:
  1. Free attacks in parallel: dmarc, contact_url, schema, smtp
  2. Score all found emails — prefer name-like over role addresses
  3. Only call Serper (google_dork) if nothing name-like was found

Usage:
  python3 domain2email.py --input stores.csv --output enriched.csv [--workers 20] [--limit 100]
  python3 domain2email.py --domain molten.world   # single domain test

Input CSV must have a `domain` column.
Optional columns used if present: `contact_page_url`, `about_us_url`

Output adds: email, email_score, email_source, email_confidence, all_emails

SERPER_API_KEY env var: optional — only used when free attacks find no name-like email.
"""

import argparse
import csv
import json
import os
import re
import smtplib
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("WARNING: dnspython not installed — DNS attacks disabled. pip install dnspython")

# ── Config ─────────────────────────────────────────────────────────────────────

HTTP_CONNECT_TO = 2
HTTP_READ_TO    = 3
SMTP_TO         = 2
DNS_TO          = 3
SMTP_PORTS      = [25, 587]
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36")

CATCHALL_PROBE = "zz-no-exist-xq7r-probe"
EMAIL_RE       = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Role prefixes that are NOT founder emails
ROLE_PREFIXES = {
    "info", "support", "hello", "contact", "sales", "shop", "team", "care",
    "help", "admin", "orders", "order", "noreply", "no-reply", "mail",
    "newsletter", "marketing", "press", "media", "pr", "service", "services",
    "customer", "office", "store", "billing", "accounts", "finance", "legal",
    "ops", "operations", "hr", "jobs", "careers", "enquiries", "enquiry",
    "inquiry", "bookings", "reservation", "reservations", "returns", "refunds",
    "wholesale", "partners", "partnerships", "affiliate", "affiliates",
    "hello", "hi", "hey", "online", "digital", "ecommerce",
    "general", "staff", "reception", "manager", "management", "feedback",
    "complaints", "questions", "ask", "post", "web", "website", "webmaster",
    "hostmaster", "postmaster", "abuse", "privacy", "security", "tech",
    "it", "dev", "developers", "api", "sys", "system", "bot", "mailer",
    "notifications", "alerts", "updates", "news", "deals", "promo", "promos",
}

# SMTP role guesses (order = empirical frequency from prior runs)
SMTP_ROLE_GUESSES = ["info", "support", "hello", "contact", "sales",
                     "shop", "team", "care", "help", "admin"]

DENY_SUFFIXES = (
    "@sentry.io", "@example.com", "@yourdomain.com", "@domain.com",
    "@shopify.com", "@myshopify.com", "@klaviyo.com", "@sendgrid.net",
    "@googletagmanager.com", "@google-analytics.com", "@mailchimp.com",
    "@mandrillapp.com", "@amazonses.com", "@constantcontact.com",
)
DENY_DMARC_DOMAINS = {
    "mailhardener.com", "dmarcian.com", "dmarc.postmarkapp.com", "agari.com",
    "valimail.com", "easydmarc.com", "uriports.com", "mxtoolbox.com",
    "dmarcanalyzer.com", "dmarcreport.com", "postmark.com", "proofpoint.com",
    "redsift.io", "reportdmarc.nl", "brevo.com",
}
DENY_DMARC_LOCALS = {
    "abuse", "postmaster", "noreply", "no-reply", "mailer-daemon", "hostmaster",
    "webmaster", "dmarc", "dmarc-reports", "dmarc_rua", "dmarc_ruf",
    "rua", "ruf", "bounces", "bounce",
}
VALID_TLDS = {
    "com", "net", "org", "io", "co", "me", "store", "shop", "uk", "us", "au",
    "de", "fr", "nl", "se", "no", "dk", "fi", "be", "at", "ch", "es", "it",
    "pt", "ca", "nz", "ie", "online", "tech", "digital", "app", "dev", "ai",
    "studio", "agency", "media", "health", "care", "life", "art", "email",
    "club", "site", "link", "social", "photography", "consulting", "solutions",
    "software", "global", "group", "clothing", "jewelry", "beauty", "fitness",
    "coffee", "garden", "pet", "food", "br", "jp", "cn", "in", "mx", "ar",
    "cl", "pe", "ec", "ru", "ua", "pl", "cz", "hu", "ro", "sk", "bg", "hr",
    "rs", "si", "lt", "lv", "ee", "tr", "gr", "cy",
}
SHOPIFY_PAGES = [
    "/pages/contact",
    "/pages/contact-us",
    "/policies/contact-information",
]
PERSONAL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "icloud.com",
                    "outlook.com", "protonmail.com", "me.com", "mac.com"}

# ── Scoring ────────────────────────────────────────────────────────────────────

def looks_like_name(local: str) -> bool:
    """True if the email local part looks like a person's name rather than a role."""
    local = local.lower()
    if local in ROLE_PREFIXES:
        return False
    # Must be mostly letters (names don't have numbers/underscores/dots at start)
    if not re.match(r"^[a-z][a-z0-9._-]{1,29}$", local):
        return False
    # Generic patterns: single repeated char, all digits, etc.
    if re.match(r"^(.)\1+$", local):
        return False
    if re.match(r"^\d+$", local):
        return False
    # Substrings that indicate a role, not a person
    role_fragments = {"order", "support", "info", "sales", "shop", "store",
                      "service", "help", "care", "team", "news", "mail",
                      "contact", "admin", "noreply", "no_reply"}
    for frag in role_fragments:
        if frag in local:
            return False
    return True


def score_email(email: str, source: str, store_domain: str) -> int:
    """
    Score an email by founder-likelihood.
    Higher = more likely to be the founder/owner.
    """
    if not email:
        return -99
    local = email.split("@")[0].lower()
    edomain = email.split("@")[1].lower() if "@" in email else ""
    score = 0

    # Name vs role
    if looks_like_name(local):
        score += 30
    elif local in ROLE_PREFIXES:
        score -= 10

    # Personal inbox (Gmail etc.) — very likely the actual founder
    if edomain in PERSONAL_DOMAINS:
        score += 15

    # Domain match — email is for this store, higher confidence
    store_apex = store_domain.lstrip("www.").lower()
    on_domain = store_apex and (edomain == store_apex or edomain.endswith("." + store_apex))
    if on_domain:
        score += 5
    elif edomain not in PERSONAL_DOMAINS:
        # Off-domain, non-personal (e.g. rescue@barcs.org for heretoy.com) — likely noise from dork
        score -= 15

    # Source quality
    source_bonus = {
        "dmarc":       5,   # owner configured DMARC — their email
        "contact_url": 3,   # from DB-provided contact page
        "schema":      2,   # scraped from site
        "smtp":       -5,   # role-guess verified — definitely a role inbox
        "google_dork": 4,   # indexed elsewhere — often press/about page
    }
    for src_key, bonus in source_bonus.items():
        if src_key in source:
            score += bonus

    return score


def best_email(candidates: list[tuple], store_domain: str = "") -> tuple:
    """
    candidates: [(email, source), ...]
    Returns (email, source, score) for the highest-scored candidate.
    """
    if not candidates:
        return None, None, 0
    scored = [(score_email(e, s, store_domain), e, s) for e, s in candidates]
    scored.sort(reverse=True)
    sc, em, src = scored[0]
    return em, src, sc


def has_founder_email(candidates: list[tuple], store_domain: str = "") -> bool:
    """True if any candidate looks like a founder email (score >= threshold)."""
    for email, source in candidates:
        if score_email(email, source, store_domain) >= 25:
            return True
    return False


# ── Helpers ────────────────────────────────────────────────────────────────────

def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def log(domain, attack, msg):
    print(f"[{ts()}] {domain:<32} [{attack:<12}] {msg}", flush=True)

def is_valid_email(e: str) -> bool:
    if not e or e.count("@") != 1:
        return False
    local, dom = e.split("@", 1)
    if not (2 <= len(local) <= 64):
        return False
    if not dom or "." not in dom:
        return False
    tld = dom.rsplit(".", 1)[-1].lower()
    return tld in VALID_TLDS

def dns_txt(name: str) -> list:
    if not HAS_DNS:
        return []
    try:
        return [str(r) for r in dns.resolver.resolve(name, "TXT", lifetime=DNS_TO)]
    except Exception:
        return []

def dns_mx(domain: str) -> str | None:
    if not HAS_DNS:
        return None
    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=DNS_TO)
        return str(min(records, key=lambda r: r.preference).exchange).rstrip(".")
    except Exception:
        try:
            parts = domain.split(".")
            if len(parts) > 2:
                apex = ".".join(parts[-2:])
                records = dns.resolver.resolve(apex, "MX", lifetime=DNS_TO)
                return str(min(records, key=lambda r: r.preference).exchange).rstrip(".")
        except Exception:
            pass
    return None

def decode_cloudflare_email(encoded: str) -> str:
    key = int(encoded[:2], 16)
    return "".join(chr(int(encoded[i:i+2], 16) ^ key) for i in range(2, len(encoded), 2))

def scrape_emails_from_html(html: str) -> list:
    found = []
    for encoded in re.findall(r'data-cfemail="([0-9a-f]+)"', html, re.I):
        try:
            e = decode_cloudflare_email(encoded).lower()
            if is_valid_email(e):
                found.append(e)
        except Exception:
            pass
    for href in re.findall(r'href=["\']mailto:([^"\'?\s]+)', html, re.I):
        found.append(href.lower().strip())
    for e in EMAIL_RE.findall(html):
        found.append(e.lower())

    seen, clean = set(), []
    for e in found:
        if e in seen:
            continue
        seen.add(e)
        if not is_valid_email(e):
            continue
        if any(e.endswith(s) for s in DENY_SUFFIXES):
            continue
        if "'" in e or "{" in e or "%" in e:
            continue
        if re.search(r"@\d+x\.(png|jpg|jpeg|webp|gif|svg)", e, re.I):
            continue
        clean.append(e)
    return clean

def lean_html(raw: str):
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup.find_all(["script", "style", "link", "noscript"]):
        tag.decompose()
    return soup, str(soup)

# ── Attacks ────────────────────────────────────────────────────────────────────

def attack_dmarc(domain: str) -> list[tuple]:
    results = []
    for txt in dns_txt(f"_dmarc.{domain}"):
        for part in txt.split(";"):
            part = part.strip().strip('"')
            if part.lower().startswith(("rua=", "ruf=")):
                for e in re.findall(r"mailto:([^\s,>]+)", part, re.I):
                    e = e.strip().lower()
                    local  = e.split("@")[0] if "@" in e else ""
                    edomain = e.split("@")[1] if "@" in e else ""
                    if (is_valid_email(e)
                            and not any(e.endswith(s) for s in DENY_SUFFIXES)
                            and not any(edomain == d or edomain.endswith("." + d)
                                        for d in DENY_DMARC_DOMAINS)
                            and local not in DENY_DMARC_LOCALS):
                        results.append((e, "dmarc"))
    return results


def attack_contact_url(domain: str, contact_url: str = None, about_url: str = None) -> list[tuple]:
    urls = [u for u in [contact_url, about_url] if u]
    if not urls:
        return []

    def fetch_and_scan(url):
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=(HTTP_CONNECT_TO, HTTP_READ_TO),
                             allow_redirects=True)
            if r.status_code != 200:
                return []
            soup, lean = lean_html(r.text)
            footer = soup.find("footer")
            emails = []
            if footer:
                emails = scrape_emails_from_html(str(footer))
            if not emails:
                emails = scrape_emails_from_html(lean)
            return [(e, f"contact_url:{url}") for e in emails]
        except Exception:
            return []

    all_found = []
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        for result in pool.map(fetch_and_scan, urls):
            all_found.extend(result)
    return all_found


def attack_schema(domain: str) -> list[tuple]:
    urls = [f"https://{domain}"] + [f"https://{domain}{p}" for p in SHOPIFY_PAGES]

    def fetch(url):
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=(HTTP_CONNECT_TO, HTTP_READ_TO),
                             allow_redirects=True)
            if r.status_code == 200:
                return url, r.text
        except Exception:
            pass
        return url, None

    pages = {}
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        for url, html in pool.map(fetch, urls):
            if html:
                pages[url] = html

    results = []

    # Homepage JSON-LD (must run before stripping scripts)
    homepage = pages.get(f"https://{domain}", "")
    if homepage:
        raw_soup = BeautifulSoup(homepage, "html.parser")
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
                            results.append((e, "schema:jsonld"))
            except Exception:
                pass

    # All pages: strip scripts, scan footer then full lean HTML
    for url, html in pages.items():
        page_key = url.split("/")[-1] or "homepage"
        soup, lean = lean_html(html)
        footer = soup.find("footer")
        if footer:
            for e in scrape_emails_from_html(str(footer)):
                results.append((e, f"schema:footer:{page_key}"))
        for e in scrape_emails_from_html(lean):
            results.append((e, f"schema:scrape:{page_key}"))

    # Deduplicate preserving first source
    seen, deduped = set(), []
    for e, src in results:
        if e not in seen:
            seen.add(e)
            deduped.append((e, src))
    return deduped


def attack_smtp(domain: str) -> list[tuple]:
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
                code, _ = smtp.rcpt(f"{CATCHALL_PROBE}@{domain}")
                if code == 250:
                    return [(f"{SMTP_ROLE_GUESSES[0]}@{domain}", f"smtp:catchall_port{port}")]
                for local in SMTP_ROLE_GUESSES:
                    email = f"{local}@{domain}"
                    code, _ = smtp.rcpt(email)
                    if code == 250:
                        return [(email, f"smtp:verified_port{port}")]
            return []
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
            continue
        except Exception:
            continue

    raise Exception(f"SMTP blocked (mx={mx})")


def attack_google_dork(domain: str, serper_key: str) -> list[tuple]:
    headers = {"X-API-KEY": serper_key, "Content-Type": "application/json"}
    role_query = " OR ".join(f"{r}@{domain}" for r in SMTP_ROLE_GUESSES[:5])
    dorks = [
        role_query,
        f"email contact site:{domain}",
        f"{domain} email contact -site:{domain}",
    ]

    results = []
    for dork in dorks:
        try:
            r = requests.post("https://google.serper.dev/search", headers=headers,
                              json={"q": dork, "num": 10}, timeout=10)
            if r.status_code != 200:
                continue
            data = r.json()
            texts = []
            for item in data.get("organic", []):
                texts.append(item.get("snippet", "") + " " + item.get("title", ""))
            texts.append(data.get("answerBox", {}).get("answer", ""))
            texts.append(data.get("answerBox", {}).get("snippet", ""))
            if "knowledgeGraph" in data:
                kg = data["knowledgeGraph"]
                texts.append(kg.get("description", ""))
                for v in kg.get("attributes", {}).values():
                    texts.append(str(v))
            for text in texts:
                for e in EMAIL_RE.findall(text):
                    e = e.lower().strip().rstrip(".")
                    if (is_valid_email(e)
                            and not any(e.endswith(s) for s in DENY_SUFFIXES)
                            and not re.search(r"@\d+x\.", e, re.I)):
                        results.append((e, f"google_dork:{dork[:40]}"))
        except Exception:
            continue

    seen, deduped = set(), []
    for e, src in results:
        if e not in seen:
            seen.add(e)
            deduped.append((e, src))
    return deduped


# ── Per-domain enrichment ──────────────────────────────────────────────────────

def enrich_domain(domain: str, contact_url: str = None, about_url: str = None,
                  serper_key: str = None) -> dict:
    t0 = time.perf_counter()
    all_candidates = []
    attack_log = {}

    # Phase 1: free attacks in parallel
    free_attacks = {
        "dmarc":       lambda: attack_dmarc(domain),
        "contact_url": lambda: attack_contact_url(domain, contact_url, about_url),
        "schema":      lambda: attack_schema(domain),
        "smtp":        lambda: attack_smtp(domain),
    }

    with ThreadPoolExecutor(max_workers=len(free_attacks)) as pool:
        futures = {pool.submit(fn): name for name, fn in free_attacks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            t1 = time.perf_counter()
            try:
                found = fut.result()
                attack_log[name] = {"found": len(found), "time": round(t1 - t0, 2)}
                all_candidates.extend(found)
            except Exception as exc:
                attack_log[name] = {"found": 0, "time": round(t1 - t0, 2), "error": str(exc)}

    # Phase 2: Google dork — only if no name-like email found yet
    dork_used = False
    if serper_key and not has_founder_email(all_candidates, domain):
        t1 = time.perf_counter()
        try:
            dork_results = attack_google_dork(domain, serper_key)
            attack_log["google_dork"] = {"found": len(dork_results), "time": round(time.perf_counter() - t1, 2)}
            all_candidates.extend(dork_results)
            dork_used = True
        except Exception as exc:
            attack_log["google_dork"] = {"found": 0, "time": 0, "error": str(exc)}

    email, source, sc = best_email(all_candidates, domain)

    # Confidence label
    if sc >= 30:
        confidence = "founder"
    elif sc >= 10:
        confidence = "role"
    elif email:
        confidence = "weak"
    else:
        confidence = "none"

    elapsed = round(time.perf_counter() - t0, 2)
    all_emails_str = "; ".join(f"{e} ({s})" for e, s in all_candidates[:8])

    return {
        "email":           email or "",
        "email_score":     sc,
        "email_source":    source or "",
        "email_confidence": confidence,
        "all_emails":      all_emails_str,
        "dork_used":       dork_used,
        "elapsed_s":       elapsed,
        "_attack_log":     attack_log,
    }


# ── CSV pipeline ───────────────────────────────────────────────────────────────

PROGRESS_SUFFIX = "_d2e_progress.json"
OUTPUT_SUFFIX   = "_enriched.csv"

def run_csv(input_path: str, output_path: str, workers: int, limit: int,
            serper_key: str, resume: bool):
    input_path  = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_suffix("").name + OUTPUT_SUFFIX
    output_path = Path(output_path)
    progress_path = input_path.with_suffix("").as_posix() + PROGRESS_SUFFIX

    # Load progress
    done = {}
    if resume and Path(progress_path).exists():
        done = json.loads(Path(progress_path).read_text())
        print(f"Resuming — {len(done)} domains already done")

    # Read input
    with open(input_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if limit:
        rows = rows[:limit]

    # Detect optional columns
    cols = rows[0].keys() if rows else []
    has_contact = "contact_page_url" in cols
    has_about   = "about_us_url" in cols

    todo = [r for r in rows if r.get("domain", "").strip() not in done]
    print(f"Total: {len(rows)} | Done: {len(done)} | To process: {len(todo)}")
    if serper_key:
        print("Serper: enabled (fallback only — skipped when name email found)")
    else:
        print("Serper: disabled (set SERPER_API_KEY to enable)")

    # Determine output fieldnames
    extra_fields = ["email", "email_score", "email_source", "email_confidence",
                    "all_emails", "dork_used", "elapsed_s"]
    existing_fields = list(rows[0].keys()) if rows else []
    out_fields = existing_fields + [f for f in extra_fields if f not in existing_fields]

    # Open output (append if resuming, write header if new)
    write_header = not (resume and output_path.exists())
    out_f = open(output_path, "a" if (resume and output_path.exists()) else "w",
                 newline="", encoding="utf-8")
    writer = csv.DictWriter(out_f, fieldnames=out_fields, extrasaction="ignore")
    if write_header:
        writer.writeheader()

    t_start = time.perf_counter()
    processed = 0
    hits = 0
    founder_hits = 0
    dork_calls = 0

    def process_row(row):
        domain = row.get("domain", "").strip()
        if not domain:
            return row, None
        contact_url = row.get("contact_page_url", "").strip() or None if has_contact else None
        about_url   = row.get("about_us_url", "").strip() or None if has_about else None
        result = enrich_domain(domain, contact_url=contact_url, about_url=about_url,
                               serper_key=serper_key)
        return row, result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(process_row, row): row for row in todo}
        for fut in as_completed(futures):
            row, result = fut.result()
            domain = row.get("domain", "").strip()
            processed += 1

            if result:
                out_row = {**row, **{k: result[k] for k in extra_fields}}
                status = f"{result['email']!r:42} conf={result['email_confidence']:<8} score={result['email_score']:>3} {result['elapsed_s']:.1f}s"
                print(f"[{ts()}] {domain:<32} {status}")
                done[domain] = result["email"]
                if result["email"]:
                    hits += 1
                if result["email_confidence"] == "founder":
                    founder_hits += 1
                if result["dork_used"]:
                    dork_calls += 1
            else:
                out_row = row

            writer.writerow(out_row)
            out_f.flush()

            # Save progress every 50 domains
            if processed % 50 == 0:
                Path(progress_path).write_text(json.dumps(done))
                elapsed = time.perf_counter() - t_start
                rate = processed / elapsed
                remaining = len(todo) - processed
                eta_min = remaining / rate / 60 if rate > 0 else 0
                print(f"  [{processed}/{len(todo)}] {hits} emails ({hits/processed*100:.0f}%) "
                      f"| {founder_hits} founder | {dork_calls} dork calls "
                      f"| {rate:.1f}/s | ETA {eta_min:.0f}m")

    out_f.close()
    Path(progress_path).write_text(json.dumps(done))

    elapsed = time.perf_counter() - t_start
    total_done = len(done)
    print(f"\n{'='*70}")
    print(f"Done: {processed} processed in {elapsed:.0f}s ({processed/elapsed:.1f}/s)")
    print(f"Emails found:   {hits}/{processed} ({hits/processed*100:.0f}%)")
    print(f"Founder emails: {founder_hits}/{processed} ({founder_hits/processed*100:.0f}%)")
    print(f"Dork calls:     {dork_calls} ({dork_calls/processed*100:.0f}% of domains)")
    print(f"Output: {output_path}")


# ── Single domain test ─────────────────────────────────────────────────────────

def run_single(domain: str, serper_key: str):
    print(f"Testing: {domain}")
    print(f"Serper:  {'enabled' if serper_key else 'disabled'}\n")
    result = enrich_domain(domain, serper_key=serper_key)
    print(f"\nEmail:       {result['email'] or '(none)'}")
    print(f"Confidence:  {result['email_confidence']} (score {result['email_score']})")
    print(f"Source:      {result['email_source']}")
    print(f"Dork used:   {result['dork_used']}")
    print(f"All found:   {result['all_emails'] or '(none)'}")
    print(f"Time:        {result['elapsed_s']}s")
    print(f"\nAttack log:")
    for name, info in result["_attack_log"].items():
        err = f" — {info['error']}" if "error" in info else ""
        print(f"  {name:<14} found={info['found']} time={info['time']}s{err}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain",  help="Test a single domain and exit")
    ap.add_argument("--input",   help="Input CSV path (requires domain column)")
    ap.add_argument("--output",  help="Output CSV path (default: <input>_enriched.csv)")
    ap.add_argument("--workers", type=int, default=20, help="Parallel domains (default 20)")
    ap.add_argument("--limit",   type=int, default=0,  help="Process at most N rows (0=all)")
    ap.add_argument("--no-resume", action="store_true", help="Ignore saved progress, start fresh")
    args = ap.parse_args()

    serper_key = os.environ.get("SERPER_API_KEY", "")

    if args.domain:
        run_single(args.domain, serper_key)
    elif args.input:
        run_csv(args.input, args.output, args.workers, args.limit,
                serper_key, resume=not args.no_resume)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
