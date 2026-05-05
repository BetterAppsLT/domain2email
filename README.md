# domain2email

Finds founder/owner emails for Shopify store domains. Built for the BetterApps outreach pipeline (cohort B — 14K stores with no email in CRM).

**Test set results: 100% coverage, 73% founder-confidence emails, ~7s per batch of 11 domains.**

---

## How it works

Runs layered attacks per domain, scores every email found, picks the best one:

| Step | Attack | Cost | What it finds |
|------|--------|------|---------------|
| 1 (parallel) | `dmarc` | free | Owner-configured DMARC RUA/RUF address |
| 1 (parallel) | `contact_url` | free | DB-provided contact/about page URLs (contactPageUrl, aboutUsUrl) |
| 1 (parallel) | `schema` | free | Homepage JSON-LD, footer emails, Cloudflare-protected addresses, Shopify contact pages |
| 1 (parallel) | `smtp` | free | MX + SMTP RCPT-TO role guessing (info@, support@, …) |
| 2 (fallback) | `google_dork` | ~$0.003/domain | Serper API — finds off-domain Gmails, press mentions, Etsy/LinkedIn bios |

**Serper is only called if the free attacks didn't surface a name-like email.** This saves ~27% of API calls on domains where schema/dmarc already finds `jen@` or similar.

### Email scoring

Every found email is scored before picking the winner:

```
+30  local part looks like a person's name (not info/sales/support/etc.)
+15  personal inbox (Gmail, Yahoo, iCloud, Protonmail…)
 +5  email domain matches the store domain
 +4  found via Google dork (indexed elsewhere — often real business contact)
 +2  found via schema scrape
-10  local part is a known role prefix
-15  off-domain AND not a personal inbox (dork noise filter)
 -5  found via SMTP role-guess (definitely a role inbox)
```

Confidence labels: **founder** (score ≥ 30) / **role** (score ≥ 10) / **weak** / **none**

---

## Install

```bash
pip install requests beautifulsoup4 dnspython
```

---

## Usage

### Single domain (test / debug)
```bash
python3 domain2email.py --domain molten.world

# With Serper fallback enabled
SERPER_API_KEY=your_key python3 domain2email.py --domain molten.world
```

### Batch CSV
```bash
# Basic run (free attacks only)
python3 domain2email.py --input stores.csv --output enriched.csv

# With Serper fallback + 20 parallel workers
SERPER_API_KEY=your_key python3 domain2email.py \
  --input stores.csv \
  --output enriched.csv \
  --workers 20

# Limit to first 500 rows (for testing)
SERPER_API_KEY=your_key python3 domain2email.py --input stores.csv --limit 500

# Start fresh (ignore saved progress)
python3 domain2email.py --input stores.csv --no-resume
```

**Resumable by default** — saves progress to `<input>_d2e_progress.json` every 50 domains. Re-running the same command picks up where it left off.

### Input CSV columns

| Column | Required | Notes |
|--------|----------|-------|
| `domain` | yes | e.g. `molten.world` |
| `contact_page_url` | no | From StoreLeads `contactPageUrl` — bypasses slug guessing |
| `about_us_url` | no | From StoreLeads `aboutUsUrl` |

### Output columns added

| Column | Example |
|--------|---------|
| `email` | `jen@thecaliforniacandleco.com` |
| `email_score` | `38` |
| `email_source` | `schema:scrape:contact-information` |
| `email_confidence` | `founder` |
| `all_emails` | `jen@... (schema:...); hello@pfcandleco.com (google_dork:...)` |
| `dork_used` | `False` |
| `elapsed_s` | `3.9` |

---

## Serper API

Sign up at [serper.dev](https://serper.dev) — $1 per 1,000 queries.

For 14K domains at ~73% dork rate × 3 queries each ≈ **~30K queries (~$30 total)**.

Rotate multiple keys by running the script in chunks:
```bash
SERPER_API_KEY=key1 python3 domain2email.py --input stores.csv --limit 3500
SERPER_API_KEY=key2 python3 domain2email.py --input stores.csv --limit 7000   # resumes from 3500
```

---

## Files

| File | Purpose |
|------|---------|
| `domain2email.py` | Production tool — use this |
| `experiment.py` | R&D runner used to tune attacks and timeouts |
| `smtp_finder.py` | Original script (from shopify-market-analysis) — kept for reference |
| `requirements.txt` | Python dependencies |

---

## Attack notes

**Why SMTP is last in scoring** — SMTP RCPT-TO only verifies role guesses (`info@`, `support@`…), never a founder's name. It's useful as a fallback but always loses to a name email from any other source.

**Why off-domain emails get -15** — Google dorks sometimes pull emails from unrelated sites that happen to mention the domain (e.g. `rescue@barcs.org` appearing in a result for `heretoy.com`). The penalty ensures these only win if they're a personal inbox (Gmail etc.), which is a strong signal the dork found the actual owner.

**`/policies/contact-information`** — standard Shopify policy page slug. High email hit rate. Added after testing showed it outperforms `/pages/contact` for some stores.

**HTML cap removed** — earlier versions capped HTML at 300KB before parsing. Emails can appear past that byte offset in Shopify pages (~900KB raw). Fix: strip `<script>`/`<style>` tags first (900KB → ~70KB lean HTML), then scan the full thing.
