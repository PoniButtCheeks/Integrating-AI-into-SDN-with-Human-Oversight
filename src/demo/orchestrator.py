#!/usr/bin/env python3
"""
End-to-end demonstration orchestrator.

  traffic -> Ryu (flow log + DNS capture) -> context API /enrich
          -> stand-in detector -> incident (provenance split)
          -> LLM agent -> deterministic validator -> human approval
          -> OVS rule on the source's access switch

A demonstration, separate from the frozen 960-trial study. Reuses
src/agent/agent.py and validator.py unchanged.

DETECTOR: a transparent rule-based stand-in over trusted controller
telemetry (host_activity). Thresholds come from observed peaks in the
captured dataset: users peak at 3 distinct destination ports and 2.1 new
flows/s, the scanner at 609 ports, the flooder at 271.7 flows/s. Servers
are skipped using the asset inventory, because their responses fan out to
many client ports and would otherwise look like attacks. Swap in the
trained model when available.

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
import subprocess
import sys
import threading
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "agent"))
from agent import recommend          # noqa: E402
from validator import validate       # noqa: E402

ENRICH_URL = "http://127.0.0.1:5001/enrich"
LOG_PATH = os.path.normpath(os.path.join(HERE, "..", "..", "data", "demo", "demo_log.jsonl"))

COOKIE = "0x5d1"          # tags every rule this script installs, for cleanup
RULE_PRIORITY = 100       # controller's own flows are priority 1
COOLDOWN_S = 60           # one incident per source per minute

POLICY = {"max_block_duration_s": 3600, "protected_hosts": ["10.0.0.20"],
          "allow_isolate": True}

SCAN_PORTS = 20
DOS_FLOWS_PS = 50

DNS_OBS_MARKERS = ("DNS", "resolve a name")
ACCESS_PORTS = {"s2": (2, 3), "s3": (2, 3)}


def sh(cmd):
    print("    $ " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("    ! " + (r.stderr.strip() or "failed"))
    return r


def get_enrich(row):
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
    r = requests.get(ENRICH_URL, params=params, timeout=5)
    r.raise_for_status()
    return r.json()


def detect(enr):
    src = (enr.get("assets") or {}).get("src") or {}
    if src.get("type") == "server":
        return "normal", 0.0, "source is a server"
    act = ((enr.get("host_activity") or {}).get("src") or {}).get("peak") or {}
    ports = act.get("out_unique_dst_ports") or 0
    fps = act.get("out_flows_per_s") or 0
    if ports >= SCAN_PORTS:
        return "port_scan", round(min(0.99, 0.5 + ports / 200), 2), \
            f"{ports} distinct destination ports"
    if fps >= DOS_FLOWS_PS:
        return "ddos", round(min(0.99, 0.5 + fps / 400), 2), \
            f"{fps} new flows per second"
    return "normal", 0.0, ""


def build_incident(row, enr, label, conf):
    obs = enr.get("observations") or []
    dns_obs = [o for o in obs if any(m in o for m in DNS_OBS_MARKERS)]
    ctl_obs = [o for o in obs if o not in dns_obs]
    assets = enr.get("assets") or {}
    trusted = {
        "ml_verdict": {"label": label, "confidence": conf,
                       "model": "rule-based stand-in"},
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
        threading.Timer(dur, sh, args=[[
            "ovs-vsctl", "set", "interface", iface,
            "ingress_policing_rate=0", "ingress_policing_burst=0"]]).start()
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


def handle(row, args, last_seen):
    src = row.get("src_ip")
    if time.time() - last_seen.get(src, 0) < COOLDOWN_S:
        return
    try:
        wait = float(row["timestamp_us"]) / 1e6 + 2.0 - time.time()
        if wait > 0:
            time.sleep(wait)
        enr = get_enrich(row)
    except Exception as e:
        print("enrich failed for %s: %s" % (src, e))
        return
    label, conf, why = detect(enr)
    if label == "normal":
        return
    last_seen[src] = time.time()

    print("\n" + "=" * 70)
    print("DETECTION  %s -> %s   %s (confidence %.2f): %s"
          % (src, row.get("dst_ip"), label, conf, why))
    inc = build_incident(row, enr, label, conf)
    if inc["untrusted_enrichment"]["dns_observations"]:
        print("UNTRUSTED  " + " | ".join(inc["untrusted_enrichment"]["dns_observations"]))

    res = recommend(inc, constrained=True,
                    separate_untrusted=not args.inline_untrusted,
                    warn_untrusted=not args.no_warning)
    rec = res.get("recommendation")
    entry = {"time": time.time(), "row": row, "enrich": enr, "incident": inc,
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
    p.add_argument("--csv", help="the controller's flow_log_full.csv")
    p.add_argument("--no-warning", action="store_true")
    p.add_argument("--inline-untrusted", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    args = p.parse_args()

    if args.cleanup:
        cleanup()
        return
    if not args.csv:
        p.error("--csv is required unless --cleanup")

    last_seen = {}
    for row in follow(args.csv):
        handle(row, args, last_seen)


if __name__ == "__main__":
    main()
