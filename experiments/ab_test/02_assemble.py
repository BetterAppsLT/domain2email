#!/usr/bin/env python3
"""
02_assemble.py — Build the final balanced A/B test list from enriched output.

Reads enriched.csv (output of domain2email.py on to_enrich.csv) and produces:
  ab_test_final.csv   — balanced, ready to import into Instantly / Lemlist

Columns in output:
  domain, merchant_name, email, email_confidence, email_source,
  cohort, pitch_type, db_email (original stale email for cohort A)

Balancing logic:
  - Filter to rows where email was found
  - Cap each cell (cohort × pitch_type) at TARGET_PER_CELL
  - Prefer founder-confidence emails within each cell
"""

import csv
import random
from collections import defaultdict
from pathlib import Path

random.seed(42)

TARGET_PER_CELL = 250
ENRICHED_CSV    = Path(__file__).parent / "enriched.csv"
OUT_CSV         = Path(__file__).parent / "ab_test_final.csv"

if not ENRICHED_CSV.exists():
    print(f"ERROR: {ENRICHED_CSV} not found.")
    print("Run domain2email.py first:\n")
    print("  cd ~/Downloads/domain2email")
    print("  SERPER_API_KEY=... python3 domain2email.py \\")
    print("    --input experiments/ab_test/to_enrich.csv \\")
    print("    --output experiments/ab_test/enriched.csv \\")
    print("    --workers 20")
    raise SystemExit(1)

# ── Load enriched data ─────────────────────────────────────────────────────────
rows = []
with open(ENRICHED_CSV) as f:
    for row in csv.DictReader(f):
        if not row.get("email", "").strip():
            continue
        rows.append(row)

print(f"Enriched rows with email: {len(rows):,}")

# ── Bucket by cell ─────────────────────────────────────────────────────────────
cells = defaultdict(list)
for row in rows:
    cohort = row.get("_cohort", "").strip()
    pitch  = row.get("_pitch",  "").strip()
    if cohort and pitch:
        cells[(cohort, pitch)].append(row)

print("\nEmails found per cell (before capping):")
for (cohort, pitch), cell_rows in sorted(cells.items()):
    founder = sum(1 for r in cell_rows if r.get("email_confidence") == "founder")
    print(f"  {cohort:<12} {pitch:<16} {len(cell_rows):>4}  ({founder} founder)")

# ── Cap each cell, prefer founder emails ──────────────────────────────────────
def sort_key(row):
    conf_order = {"founder": 0, "role": 1, "weak": 2, "none": 3}
    return (conf_order.get(row.get("email_confidence", "none"), 3),
            -int(row.get("email_score", 0) or 0))

final_rows = []
for (cohort, pitch), cell_rows in cells.items():
    cell_rows.sort(key=sort_key)
    selected = cell_rows[:TARGET_PER_CELL]
    for row in selected:
        row["cohort"]     = cohort
        row["pitch_type"] = pitch
        row["db_email"]   = row.get("emails", "")   # original stale DB email
    final_rows.extend(selected)

# ── Stats ──────────────────────────────────────────────────────────────────────
print(f"\nFinal list: {len(final_rows):,} rows")
print("\nPer cell:")
print(f"  {'Cohort':<12} {'Pitch':<16} {'Count':>6}  {'Founder%':>9}  {'Has DB email':>13}")
print("  " + "-"*60)
for (cohort, pitch) in sorted(cells.keys()):
    cell = [r for r in final_rows if r["cohort"] == cohort and r["pitch_type"] == pitch]
    if not cell: continue
    founder_pct = sum(1 for r in cell if r.get("email_confidence") == "founder") / len(cell) * 100
    has_db      = sum(1 for r in cell if r.get("db_email", "").strip())
    print(f"  {cohort:<12} {pitch:<16} {len(cell):>6}  {founder_pct:>8.0f}%  {has_db:>13}")

# ── Write output ───────────────────────────────────────────────────────────────
out_fields = [
    "domain", "merchant_name", "email", "email_confidence", "email_score",
    "email_source", "cohort", "pitch_type", "db_email",
    "country_code", "estimated_monthly_sales", "all_emails",
]

with open(OUT_CSV, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=out_fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(final_rows)

print(f"\nWrote: {OUT_CSV}")
print("\nImport ab_test_final.csv into Instantly/Lemlist.")
print("Segment by cohort + pitch_type for the 6-cell A/B test.")
