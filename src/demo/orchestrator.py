#!/usr/bin/env python3
"""
End-to-end demonstration orchestrator.

  traffic -> Ryu (flow log + DNS capture) -> ML detector
          -> context API /enrich -> incident (provenance split)
          -> LLM agent -> deterministic validator -> human approval
          -> OVS rule on the source's access switch

A demonstration, separate from the frozen 960-trial study. Reuses
src/agent/agent.py and validator.py unchanged.

DETECTOR: the team's XGBoost model trained on network_capture_v2
(models/best_model_payload_free.pkl), which classifies each flow row from
4 flow-log columns. One attack produces many flows, so an incident is
raised when MIN_FLAGGED flows from the same source get the same attack
label within WINDOW_S seconds of row time; confidence is their mean
probability. With the model's 0.31% per-flow false-positive rate on
normal traffic, a user at about 2 flows/s would need 5 misclassified
flows in 30 s, which is negligible. Servers are still skipped using the
asset inventory, because their responses fan out to many client ports.

PROVENANCE: /enrich does not label where each piece of context came from,
so DNS-derived content is identified by field (the dns block) and by
matching the context API's DNS sentence templates. Adequate for a
demonstration. Not a security boundary.

Run with sudo, since OVS commands need root, using the ML venv's python:
  sudo ~/venvs/ml/bin/python ~/sdnproj/src/demo/orchestrator.py --csv PATH
Remove all demo rules afterwards:
  sudo ~/venvs/ml/bin/python ~/sdnproj/src/demo/orchestrator.py --cleanup
"""

import argparse
import json
import os
import pickle
import subprocess
import sys
import threading
import time
from collections import deque

import pandas as pd
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "agent"))
from agent import recommend          # noqa: E402
from validator import validate       # noqa: E402

ENRICH_URL = "http://127.0.0.1:5001/enrich"
ASSETS_URL = "http://127.0.0.1:5001/assets"
LOG_PATH = os.path.normpath(os.path.join(HERE, "..", "..", "data", "demo", "demo_log.jsonl"))

COOKIE = "0x5d1"          # tags every rule this script installs, for cleanup
RULE_PRIORITY = 100       # controller's own flows are priority 1
COOLDOWN_S = 60           # one incident per source per minute of row time

POLICY = {"max_block_duration_s": 3600, "protected_hosts": ["10.0.0.20"],
          "allow_isolate": True}

MODEL_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "models"))
MODEL_PATH = os.path.join(MODEL_DIR, "best_model_payload_free.pkl")
META_PATH = os.path.join(MODEL_DIR, "label_map_payload_free.json")
MODEL_NAME = "XGBoost, payload-free features (best_model_payload_free.pkl)"
WINDOW_S = 30
MIN_FLAGGED = 5
# Same label strings the stand-in and the frozen experiment incidents used,
# so the agent and validator see the vocabulary they were tested with.
INCIDENT_LABEL = {"portscan": "port_scan", "dos": "ddos"}

MODEL = None
META = None
SERVERS = set()

DNS_OBS_MARKERS = ("DNS", "resolve a name")
ACCESS_PORTS = {"s2": (2, 3), "s3": (2, 3)}


def sh(cmd):
    print("    $ " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("    ! " + (r.stderr.strip() or "failed"))
    return r


def get_enrich(row, swapped=False):
    def num(k):
        try:
            return int(float(row[k]))
        except (KeyError, ValueError):
            return None
    params = {"log_ts_us": row["timestamp_us"], "src_ip": row["src_ip"],
              "dst_ip": row["dst_ip"]}
    for k in ("src_port", "dst_port", "protocol"):
        if num(k) is not None:
            params[k] = num(k)
    if swapped:
        # flow_detail is stored under the logged direction, so /enrich will not
        # find it; give it the window explicitly instead of its default.
        ts_us = float(row["timestamp_us"])
        params["start_us"], params["end_us"] = ts_us - 30e6, ts_us
    r = requests.get(ENRICH_URL, params=params, timeout=5)
    r.raise_for_status()
    return r.json()


def load_model():
    global MODEL, META
    with open(META_PATH) as f:
        META = json.load(f)
    with open(MODEL_PATH, "rb") as f:
        MODEL = pickle.load(f)
    print("model loaded: %s, features %s" % (MODEL_NAME, META["feature_names"]))


def load_servers():
    global SERVERS
    assets = requests.get(ASSETS_URL, timeout=5).json()["assets"]
    SERVERS = {ip for ip, a in assets.items() if a.get("type") == "server"}
    print("servers from asset inventory: %s" % sorted(SERVERS))


def actor_view(row):
    # Under load the controller sometimes logs a client's flow with the server's
    # reply as the initiator (seen live with a SYN flood: every row logged as
    # srv-crit -> h_atk). Servers never initiate in this topology, so attribute
    # such a row to the client end. Classification still uses the row as logged.
    if row.get("src_ip") in SERVERS and row.get("dst_ip") not in SERVERS:
        return dict(row, src_ip=row["dst_ip"], dst_ip=row["src_ip"],
                    src_port=row.get("dst_port"), dst_port=row.get("src_port")), True
    return row, False


def classify(row):
    try:
        x = pd.DataFrame([[float(row[c]) for c in META["csv_column_names"]]],
                         columns=META["feature_names"])
    except (KeyError, ValueError):
        return "normal", 0.0
    proba = MODEL.predict_proba(x)[0]
    code = int(proba.argmax())
    return META["code_to_label"][str(code)], float(proba[code])


def detect(row, view, windows):
    label, prob = classify(row)
    if label == "normal":
        return None
    ts = float(row["timestamp_us"]) / 1e6
    win = windows.setdefault(view.get("src_ip"), deque())
    win.append((ts, label, prob, view.get("dst_port")))
    while win and win[0][0] < ts - WINDOW_S:
        win.popleft()
    hits = [w for w in win if w[1] == label]
    if len(hits) < MIN_FLAGGED:
        return None
    conf = round(sum(h[2] for h in hits) / len(hits), 2)
    why = "%d flows in %ds classified %s by the ML model, %d distinct destination ports" % (
        len(hits), WINDOW_S, label, len({h[3] for h in hits}))
    return INCIDENT_LABEL[label], conf, why, len(hits)


def build_incident(row, enr, label, conf, flagged):
    obs = enr.get("observations") or []
    dns_obs = [o for o in obs if any(m in o for m in DNS_OBS_MARKERS)]
    ctl_obs = [o for o in obs if o not in dns_obs]
    assets = enr.get("assets") or {}
    trusted = {
        "ml_verdict": {"label": label, "confidence": conf,
                       "model": MODEL_NAME,
                       "flows_flagged_in_window": flagged,
                       "window_s": WINDOW_S},
        "flow": {k: row.get(k) for k in (
            "src_ip", "dst_ip", "protocol", "dst_port",
            "total_packets", "duration_us")},
        "flow_detail": enr.get("flow_detail"),
        "source_host": assets.get("src"),
        "target_asset": assets.get("dst"),
        "host_activity": enr.get("host_activity"),
        "switch": enr.get("switch"),
        "service_health": enr.get("service_health"),
        "controller_observations": ctl_obs,
        "site_policy_notes": enr.get("policy"),
        "policy": POLICY,
    }
    untrusted = {"dns": enr.get("dns"), "dns_observations": dns_obs}
    return {"event_id": "live-%s-%d" % (row["src_ip"], int(time.time())),
            "trusted": trusted, "untrusted_enrichment": untrusted}


def apply(action, rec, enr):
    src = (enr.get("assets") or {}).get("src") or {}
    sw, port = src.get("switch"), src.get("switch_port")
    ip = rec["target_ip"]
    dst = (enr.get("flow") or {}).get("dst_ip")
    dur = int(rec.get("duration_s") or 300)
    if not sw:
        print("    no access switch known for this source, nothing applied")
        return
    add = ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", sw]
    base = "cookie=%s,priority=%d,hard_timeout=%d,ip" % (COOKIE, RULE_PRIORITY, dur)
    if action == "ISOLATE":
        sh(add + ["%s,nw_src=%s,actions=drop" % (base, ip)])
        sh(add + ["%s,nw_dst=%s,actions=drop" % (base, ip)])
    elif action == "BLOCK":
        sh(add + ["%s,nw_src=%s,nw_dst=%s,actions=drop" % (base, ip, dst)])
    elif action == "RATE_LIMIT":
        iface = "%s-eth%s" % (sw, port)
        sh(["ovs-vsctl", "set", "interface", iface,
            "ingress_policing_rate=100", "ingress_policing_burst=10"])
        # Daemon, so Ctrl+C exits at once; --cleanup resets any limit still on.
        t = threading.Timer(dur, sh, args=[[
            "ovs-vsctl", "set", "interface", iface,
            "ingress_policing_rate=0", "ingress_policing_burst=0"]])
        t.daemon = True
        t.start()
    else:
        print("    %s: no network change" % action)


def cleanup():
    for sw in ("s1", "s2", "s3", "s4"):
        sh(["ovs-ofctl", "-O", "OpenFlow13", "del-flows", sw, "cookie=%s/-1" % COOKIE])
    for sw, ports in ACCESS_PORTS.items():
        for p in ports:
            sh(["ovs-vsctl", "set", "interface", "%s-eth%d" % (sw, p),
                "ingress_policing_rate=0", "ingress_policing_burst=0"])


def log(entry):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def follow(path):
    print("waiting for %s ..." % path)
    while not os.path.exists(path):
        time.sleep(1)
    with open(path) as f:
        header = f.readline().strip().split(",")
        f.seek(0, 2)
        buf = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(1)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue
            yield dict(zip(header, buf.strip().split(",")))
            buf = ""


def handle(logged, args, last_seen, windows):
    try:
        ts = float(logged["timestamp_us"]) / 1e6
    except (KeyError, ValueError):
        return
    row, swapped = actor_view(logged)
    src = row.get("src_ip")
    # Row time, not wall time: rows that queue up while the operator is
    # answering a prompt must not raise a second incident for the same attack.
    if ts - last_seen.get(src, 0) < COOLDOWN_S:
        return
    hit = detect(logged, row, windows)
    if hit is None:
        return
    label, conf, why, flagged = hit
    try:
        wait = ts + 2.0 - time.time()
        if wait > 0:
            time.sleep(wait)
        enr = get_enrich(row, swapped)
    except Exception as e:
        print("enrich failed for %s: %s" % (src, e))
        return
    last_seen[src] = ts
    windows.pop(src, None)
    if ((enr.get("assets") or {}).get("src") or {}).get("type") == "server":
        return

    print("\n" + "=" * 70)
    print("DETECTION  %s -> %s   %s (confidence %.2f): %s"
          % (src, row.get("dst_ip"), label, conf, why))
    if swapped:
        print("           flow was logged server-first; attributed to the client end")
    inc = build_incident(row, enr, label, conf, flagged)
    if inc["untrusted_enrichment"]["dns_observations"]:
        print("UNTRUSTED  " + " | ".join(inc["untrusted_enrichment"]["dns_observations"]))

    res = recommend(inc, constrained=True,
                    separate_untrusted=not args.inline_untrusted,
                    warn_untrusted=not args.no_warning)
    rec = res.get("recommendation")
    entry = {"time": time.time(), "row": row, "logged_row": logged,
             "direction_swapped": swapped, "enrich": enr, "incident": inc,
             "recommendation": rec, "flags": vars(args)}
    if rec is None:
        print("LLM gave no structured recommendation")
        log(dict(entry, decision="none"))
        return

    print("LLM        %s on %s for %ss  (injection suspected: %s)"
          % (rec.get("action"), rec.get("target_ip"), rec.get("duration_s"),
             rec.get("injection_suspected")))
    print("           " + str(rec.get("reasoning", ""))[:300])

    ok, reasons = validate(inc["trusted"], rec)
    entry["validator"] = {"passed": ok, "reasons": reasons}
    if not ok:
        print("VALIDATOR  REFUSED: " + "; ".join(reasons))
        print("           escalated to operator, nothing applied")
        log(dict(entry, decision="refused_by_validator"))
        return
    print("VALIDATOR  accepted")

    answer = input("OPERATOR   apply %s? [y/N] " % rec["action"]).strip().lower()
    if answer == "y":
        apply(rec["action"], rec, enr)
        log(dict(entry, decision="approved"))
    else:
        print("           declined, nothing applied")
        log(dict(entry, decision="declined"))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", help="the controller's flow_log.csv")
    p.add_argument("--no-warning", action="store_true")
    p.add_argument("--inline-untrusted", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    args = p.parse_args()

    if args.cleanup:
        cleanup()
        return
    if not args.csv:
        p.error("--csv is required unless --cleanup")

    load_model()
    load_servers()
    last_seen, windows = {}, {}
    for row in follow(args.csv):
        handle(row, args, last_seen, windows)


if __name__ == "__main__":
    main()
