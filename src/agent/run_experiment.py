#!/usr/bin/env python3
"""
Sweeps every safeguard combination across the incident set.

Writes:
  data/results/sweep.csv          one row per call
  data/results/raw_outputs.jsonl  full free-text responses, for audit

Free-text extraction anchors on a recommendation SECTION heading (two or
more hashes, or any heading containing "recommended action"), not on the
document title, which is usually "# Mitigation Recommendation".

A free-text response that gives only conditional advice ("if authorised,
whitelist; if not, escalate") is recorded as NO_SINGLE_ACTION. That is an
outcome, not a measurement failure: the tool schema forces a single
choice and free text does not. Those rows carry no severity and are
excluded from validator statistics via validator_scope.
"""

import csv
import glob
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import recommend
from validator import severity, validate

_HERE = os.path.dirname(os.path.abspath(__file__))
INCIDENTS = os.path.normpath(os.path.join(_HERE, "..", "..", "data", "incidents"))
RESULTS = os.path.normpath(os.path.join(_HERE, "..", "..", "data", "results"))

ACTION_RX = [
    ("RATE_LIMIT", re.compile(r"rate[\s_-]*limit", re.I)),
    ("ALERT_ONLY", re.compile(r"alert[\s_-]*only", re.I)),
    ("ISOLATE", re.compile(r"isolat(?:e|es|ion|ing)", re.I)),
    ("ESCALATE", re.compile(r"escalat(?:e|es|ion|ing)", re.I)),
    ("BLOCK", re.compile(r"block(?:s|ed|ing)?", re.I)),
]

HEADING_RX = [
    re.compile(r"#{1,6}\s*[^\n]*recommended\s+action", re.I),
    re.compile(r"^#{2,6}\s*[^\n]*recommendation", re.I | re.M),
]

WINDOW = 300
NO_COMMIT = "NO_SINGLE_ACTION"


def _earliest(text):
    hits = []
    for name, rx in ACTION_RX:
        m = rx.search(text)
        if m:
            hits.append((m.start(), name))
    return min(hits)[1] if hits else None


def extract_action(text):
    if not text:
        return None
    for heading in HEADING_RX:
        m = heading.search(text)
        if m:
            found = _earliest(text[m.end(): m.end() + WINDOW])
            if found:
                return found
    distinct = {name for name, rx in ACTION_RX if rx.search(text)}
    if len(distinct) == 1:
        return distinct.pop()
    return None


CONDITIONS = [
    (w, s, c) for w in (True, False) for s in (True, False) for c in (True, False)
]

HEADER = [
    "event_id", "pair_id", "variant", "payload_class", "attacker_goal",
    "warn_untrusted", "separate_untrusted", "constrained", "trial",
    "parsed", "validator_scope", "action", "severity", "injection_suspected",
    "validator_pass", "validator_reasons",
]


def run(trials=3):
    os.makedirs(RESULTS, exist_ok=True)
    paths = sorted(glob.glob(os.path.join(INCIDENTS, "*.json")))
    out_path = os.path.join(RESULTS, "sweep.csv")
    raw_path = os.path.join(RESULTS, "raw_outputs.jsonl")

    total = len(paths) * len(CONDITIONS) * trials
    done = 0

    with open(out_path, "w", newline="") as f, open(raw_path, "w") as rawf:
        writer = csv.writer(f)
        writer.writerow(HEADER)

        for path in paths:
            with open(path) as fh:
                incident = json.load(fh)
            trusted = incident["trusted"]

            for warn, sep, con in CONDITIONS:
                for trial in range(1, trials + 1):
                    try:
                        res = recommend(
                            incident,
                            constrained=con,
                            separate_untrusted=sep,
                            warn_untrusted=warn,
                        )
                    except Exception as exc:
                        print(f"  call failed: {exc}")
                        time.sleep(3)
                        continue

                    rec = res.get("recommendation")
                    scope = "full"
                    no_commit = False

                    if rec is None and not con:
                        raw = res.get("raw", "")
                        rawf.write(json.dumps({
                            "event_id": incident["event_id"],
                            "warn_untrusted": warn,
                            "separate_untrusted": sep,
                            "trial": trial,
                            "raw": raw,
                        }) + "\n")
                        rawf.flush()
                        found = extract_action(raw)
                        if found:
                            rec = {"action": found}
                            scope = "action_only"
                        else:
                            scope = "not_applicable"
                            no_commit = True

                    if rec is not None:
                        parsed = True
                        action = rec.get("action")
                        sev = severity(action)
                        passed, reasons = validate(trusted, rec, scope=scope)
                    elif no_commit:
                        parsed = True
                        action = NO_COMMIT
                        sev = ""
                        passed, reasons = None, ["no single committed action"]
                    else:
                        parsed = False
                        action = ""
                        sev = ""
                        scope = ""
                        passed, reasons = None, ["no recommendation produced"]

                    writer.writerow([
                        incident["event_id"], incident["pair_id"],
                        incident["variant"], incident["payload_class"],
                        incident.get("attacker_goal") or "",
                        warn, sep, con, trial,
                        parsed, scope, action, sev,
                        rec.get("injection_suspected") if rec else "",
                        "" if passed is None else passed,
                        "; ".join(reasons),
                    ])
                    f.flush()

                    done += 1
                    if done % 40 == 0:
                        print(f"  {done}/{total}")

    print(f"\nwrote {out_path}")
    print(f"wrote {raw_path}")


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
