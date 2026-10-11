#!/usr/bin/env python3
"""
Deterministic truth table for validator.py.

The validator contains no model call, so its complete behaviour can be
enumerated rather than sampled. This runs every allowed action against
every scenario's trusted evidence and reports accept or reject. No API
calls, no cost.

target_ip and duration_s are held at valid values throughout, so the
table isolates the action-based policy: the severity floor and the
isolate permission.

This documents the frozen validator. It does not modify it.
"""

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validator import CONFIDENCE_FLOOR, SEVERITY, validate

_HERE = os.path.dirname(os.path.abspath(__file__))
INCIDENTS = os.path.normpath(os.path.join(_HERE, "..", "..", "data", "incidents"))
RESULTS = os.path.normpath(os.path.join(_HERE, "..", "..", "data", "results"))
OUT = os.path.join(RESULTS, "VALIDATOR_TRUTH_TABLE.md")

ACTIONS = sorted(SEVERITY, key=lambda a: SEVERITY[a])


def derived_floor(trusted):
    """Reproduce the validator's floor so the table shows why, not just what."""
    v = trusted["ml_verdict"]
    if v["label"] == "normal":
        return None
    return "RATE_LIMIT" if v["confidence"] >= CONFIDENCE_FLOOR else "ESCALATE"


# The trusted block is identical across a scenario's five enrichment
# variants, so one incident per scenario is sufficient.
scenarios = {}
for path in sorted(glob.glob(os.path.join(INCIDENTS, "*.json"))):
    inc = json.load(open(path))
    scenarios.setdefault(inc["pair_id"], inc)

header = ["scenario", "verdict", "conf", "floor"] + ACTIONS
rows = []

for pair_id, inc in sorted(scenarios.items()):
    t = inc["trusted"]
    v = t["ml_verdict"]
    base = {"target_ip": t["flow"]["src_ip"], "duration_s": 300}
    cells = []
    for action in ACTIONS:
        ok, _ = validate(t, dict(base, action=action))
        cells.append("accept" if ok else "REJECT")
    rows.append([pair_id, v["label"], f"{v['confidence']:.2f}",
                 str(derived_floor(t))] + cells)

widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
line = lambda r: "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r))

print("=" * 74)
print("VALIDATOR TRUTH TABLE")
print("every action against every scenario, action rules only")
print("=" * 74)
print(line(header))
print(line(["-" * w for w in widths]))
for r in rows:
    print(line(r))
print()
print(f"Severity ordering: " + " < ".join(f"{a}({SEVERITY[a]})" for a in ACTIONS))
print(f"Confidence threshold for the higher floor: {CONFIDENCE_FLOOR}")
print()
print("Note: ALERT_ONLY is below the floor for every non-normal verdict at")
print("any confidence. Since ALERT_ONLY is the attacker goal in every")
print("injected payload, the validator refusing all full-suppression")
print("attempts is a property of the design, not an experimental result.")

md = ["# Validator truth table", "",
      "Deterministic enumeration of `validator.py`. No model calls.",
      "`target_ip` and `duration_s` held valid, so this isolates the "
      "action-based policy.", "",
      "| " + " | ".join(header) + " |",
      "|" + "|".join(["---"] * len(header)) + "|"]
for r in rows:
    md.append("| " + " | ".join(str(c) for c in r) + " |")
md += ["",
       "Severity ordering: " + " < ".join(f"`{a}` ({SEVERITY[a]})" for a in ACTIONS),
       "",
       f"Confidence threshold for the higher floor: {CONFIDENCE_FLOOR}", "",
       "`ALERT_ONLY` sits below the floor for every non-normal verdict at any",
       "confidence. It is also the attacker goal in every injected payload, so",
       "the validator refusing all full-suppression attempts follows from the",
       "design rather than being an experimental result."]

os.makedirs(RESULTS, exist_ok=True)
with open(OUT, "w") as f:
    f.write("\n".join(md))
print(f"wrote {OUT}")
