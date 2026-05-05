#!/usr/bin/env python3
"""
01_sample.py — Sample stores for A/B test.

Outputs:
  to_enrich.csv   — ALL sampled stores (both cohorts) to run through domain2email

domain2email runs on everything. The cohort split (A=stale DB email, B=no prior email)
is preserved as metadata for analysis after enrichment, not used to skip enrichment.

6 test cells after enrichment:
  pitch_type × cohort = {both, post_purchase, popup} × {A_email, B_no_email}

Target 250 confirmed emails per cell = 1,500 total.
Cohort B over-sampled by 1/0.75 to account for ~75% email hit rate.
Popup cell uses all 390 B_no_email available (binding constraint).
Cohort A sampled to same size per pitch type.
"""

import csv
import json
import random
from collections import defaultdict
from pathlib import Path

random.seed(42)

# ── Config ─────────────────────────────────────────────────────────────────────
CRM_CSV      = Path.home() / "Downloads/shopify_leads_ab.csv"
CLASS_CSV    = Path(__file__).parent.parent / "app_classification/app_classifications.csv"
CHECKPOINT   = Path(__file__).parent.parent / "app_classification/classify_checkpoint.json"
OUT_DIR      = Path(__file__).parent

TARGET_PER_CELL  = 250
EMAIL_HIT_RATE   = 0.75   # expected domain2email hit rate on cohort B

# ── Load app classifications ───────────────────────────────────────────────────
cats = {}
with open(CLASS_CSV) as f:
    for row in csv.DictReader(f):
        cats[row["name"]] = row["category"]
cp = json.loads(CHECKPOINT.read_text())
for name, cat in cp.items():
    if name not in cats:
        cats[name] = cat

PP_CATS = {"post_purchase_upsell", "mixed_includes_post_purchase", "mixed_includes_both"}
PU_CATS = {"popup_upsell", "mixed_includes_popup", "mixed_includes_both"}

def pitch_type(apps):
    pp = any(cats.get(a, "") in PP_CATS for a in apps)
    pu = any(cats.get(a, "") in PU_CATS for a in apps)
    if pp and pu:  return None           # has both — skip
    if not pp and not pu: return "both"  # pitch both products
    if pp:         return "popup"        # has PP, pitch popup upsell
    return "post_purchase"               # has popup, pitch post-purchase

# ── Bucket all useful stores ───────────────────────────────────────────────────
buckets = defaultdict(list)  # (cohort, pitch) -> [row, ...]

with open(CRM_CSV) as f:
    for row in csv.DictReader(f):
        cohort   = row.get("cohort", "").strip()
        apps_str = row.get("installed_apps_names", "").strip()
        apps     = [a.strip() for a in apps_str.split(":") if a.strip()] if apps_str else []
        pt       = pitch_type(apps)
        if not pt:
            continue
        buckets[(cohort, pt)].append(row)

print("Available stores per bucket:")
for key, rows in sorted(buckets.items()):
    print(f"  {key[0]:<12} {key[1]:<16} {len(rows):>6,}")

# ── Sample cohort B (to enrich) ───────────────────────────────────────────────
# Popup is binding: use all 390. Scale other targets proportionally.
popup_b   = buckets[("B_no_email", "popup")]
n_popup_b = len(popup_b)                          # 390
# Over-sample so after ~75% hit rate we still hit TARGET_PER_CELL
n_both_b  = min(len(buckets[("B_no_email", "both")]),
                int(TARGET_PER_CELL / EMAIL_HIT_RATE))
n_pp_b    = min(len(buckets[("B_no_email", "post_purchase")]),
                int(TARGET_PER_CELL / EMAIL_HIT_RATE))

b_both   = random.sample(buckets[("B_no_email", "both")],         n_both_b)
b_pp     = random.sample(buckets[("B_no_email", "post_purchase")], n_pp_b)
b_popup  = popup_b   # all of them

cohort_b_sample = []
for row in b_both:   row["_pitch"] = "both";          cohort_b_sample.append(row)
for row in b_pp:     row["_pitch"] = "post_purchase";  cohort_b_sample.append(row)
for row in b_popup:  row["_pitch"] = "popup";          cohort_b_sample.append(row)

random.shuffle(cohort_b_sample)

print(f"\nCohort B to enrich: {len(cohort_b_sample):,} domains")
print(f"  both:           {n_both_b}")
print(f"  post_purchase:  {n_pp_b}")
print(f"  popup:          {n_popup_b}  (all available)")
print(f"  Expected emails after enrichment: ~{int(len(cohort_b_sample)*EMAIL_HIT_RATE)}")

# ── Sample cohort A (already has email) ───────────────────────────────────────
# Match TARGET_PER_CELL per pitch type, only rows that actually have an email
a_has_email = {pt: [r for r in buckets[("A_email", pt)] if r.get("emails","").strip()]
               for pt in ("both", "post_purchase", "popup")}

n_a = TARGET_PER_CELL
a_both  = random.sample(a_has_email["both"],          min(n_a, len(a_has_email["both"])))
a_pp    = random.sample(a_has_email["post_purchase"],  min(n_a, len(a_has_email["post_purchase"])))
a_popup = random.sample(a_has_email["popup"],          min(n_a, len(a_has_email["popup"])))

cohort_a_sample = []
for row in a_both:   row["_pitch"] = "both";          cohort_a_sample.append(row)
for row in a_pp:     row["_pitch"] = "post_purchase";  cohort_a_sample.append(row)
for row in a_popup:  row["_pitch"] = "popup";          cohort_a_sample.append(row)

print(f"\nCohort A sampled: {len(cohort_a_sample):,} stores (already have email)")
print(f"  both:           {len(a_both)}")
print(f"  post_purchase:  {len(a_pp)}")
print(f"  popup:          {len(a_popup)}")

# ── Merge and write single enrichment input ───────────────────────────────────
all_sample = cohort_b_sample + cohort_a_sample
random.shuffle(all_sample)

fields = ["domain", "_pitch", "_cohort", "emails", "merchant_name",
          "country_code", "estimated_monthly_sales", "installed_apps_names"]

# Tag cohort
for row in cohort_b_sample: row["_cohort"] = "B_no_email"
for row in cohort_a_sample: row["_cohort"] = "A_email"

with open(OUT_DIR / "to_enrich.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(all_sample)

total = len(all_sample)
print(f"\nWrote: to_enrich.csv ({total:,} rows — both cohorts)")
print(f"\nEstimated Serper usage:")
serper_calls = int(total * 0.73 * 3)
print(f"  {total} domains × 73% dork rate × 3 queries = ~{serper_calls:,} credits")
print(f"  Budget: 7,426 credits  →  {'OK' if serper_calls < 7426 else 'OVER BUDGET'}")
print(f"\nNext step:")
print(f"  cd ~/Downloads/domain2email")
print(f"  SERPER_API_KEY=... python3 domain2email.py \\")
print(f"    --input experiments/ab_test/to_enrich.csv \\")
print(f"    --output experiments/ab_test/enriched.csv \\")
print(f"    --workers 20")
print(f"\nThen: python3 experiments/ab_test/02_assemble.py")
