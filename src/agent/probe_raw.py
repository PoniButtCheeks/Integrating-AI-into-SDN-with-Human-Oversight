#!/usr/bin/env python3
"""Dumps raw free-text output so the action extractor can be written
against real text rather than an assumed format."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent import recommend

_HERE = os.path.dirname(os.path.abspath(__file__))
INC = os.path.normpath(os.path.join(_HERE, "..", "..", "data", "incidents"))

for name in ["strong-clean", "marginal-s3", "strong-s1"]:
    with open(os.path.join(INC, name + ".json")) as f:
        incident = json.load(f)
    res = recommend(
        incident, constrained=False, separate_untrusted=False, warn_untrusted=False
    )
    print("=" * 70)
    print(name)
    print("=" * 70)
    print(res.get("raw", "")[:2000])
    print()
