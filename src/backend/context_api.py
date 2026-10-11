#!/usr/bin/env python3
"""
Context API for the LLM agent.

Start this BEFORE the RYU controller:
    pip install flask --break-system-packages   # one-time
    python3 context_api.py

PRODUCERS (push records with POST /context, one object or a list):
    controller  -> kind = dns | arp | host_activity | port_stats | table_stats | controller_load | flow_detail
    traffic_gen -> kind = service_probe   (HTTP/DNS health probes run server-to-server)

CONSUMER (the LLM agent):
    GET /enrich?log_ts_us=<timestamp_us of the CSV row>&src_ip=..&dst_ip=..&src_port=..&dst_port=..
        (the five values come straight from a flow_log.csv row; start/end times and the
         per-flow detail are looked up automatically from the flow_detail record)
        One call that returns everything known about a flow: asset info, DNS,
        source/destination behaviour, switch/link load, service health, ARP
        bindings, plus a list of plain-language `observations`.
    GET /context, /context/latest, /assets   -- raw access

IMPORTANT: no ground-truth labels or attacker/scanner roles live here. The LLM
must only see what a real operator could know. Labels stay in the flow CSV
and scenario_windows.csv (for evaluation only).
"""

import json
import os
import statistics
import threading
import time
from collections import deque

from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_IN_MEMORY = 20000
_records = deque(maxlen=MAX_IN_MEMORY)
_lock = threading.Lock()
PERSIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context_log.jsonl")

# ---------------------------------------------------------------------------
# Static knowledge: asset inventory (CMDB), topology, policy.
# Keep this in sync with THE-TOPOLOGY.py (link order decides the switch port numbers).
# Hosts are described the way an operator would see them, so no attacker/scanner roles.
# ---------------------------------------------------------------------------
def _ws(host, sw, port):
    return {"hostname": host, "type": "workstation", "criticality": "low",
            "switch": sw, "switch_port": port, "expected_services": [],
            "description": "User workstation (client only)"}

ASSETS = {
    "10.0.0.10": _ws("ws-10", "s2", 2),
    "10.0.0.11": _ws("ws-11", "s2", 3),
    "10.0.0.12": _ws("ws-12", "s3", 2),
    "10.0.0.13": _ws("ws-13", "s3", 3),
    "10.0.0.20": {"hostname": "srv-crit", "type": "server", "criticality": "high",
                  "switch": "s4", "switch_port": 2,
                  "expected_services": ["tcp/80 http"],
                  "description": "Business-critical application server"},
    "10.0.0.21": {"hostname": "srv-low", "type": "server", "criticality": "low",
                  "switch": "s4", "switch_port": 3,
                  "expected_services": ["udp/53 dns", "tcp/80 http", "tcp/443 https"],
                  "description": "Low-priority internal web/DNS server"},
}

# dpid -> port -> what's attached (same order as addLink in THE-TOPOLOGY.py).
PORT_MAP = {
    1: {1: "link to s2 (access: ws-10, ws-11)",
        2: "link to s3 (access: ws-12, ws-13)",
        3: "link to s4 (servers srv-crit, srv-low)"},
    2: {1: "uplink to s1", 2: "ws-10", 3: "ws-11"},
    3: {1: "uplink to s1", 2: "ws-12", 3: "ws-13"},
    4: {1: "uplink to s1", 2: "srv-crit", 3: "srv-low"},
}
# The links have no bandwidth set in this topology, so no utilisation %, just absolute rates.
BUSY_LINK_PPS = 1000     # a core link above this gets mentioned

POLICY = [
    "Workstations are clients only: they initiate connections to servers (HTTP 80, HTTPS 443, DNS 53) and host no services.",
    "Servers should only receive traffic on the ports listed in their expected_services.",
    "Normal clients usually resolve a name via DNS before connecting; connecting to a bare IP with no prior lookup is unusual but not conclusive.",
    "A workstation normally opens a few new flows per second at most, to a handful of destinations and ports.",
]


# ---------------------------------------------------------------------------
# Ingest and raw queries
# ---------------------------------------------------------------------------
@app.route("/context", methods=["POST"])
def post_context():
    body = request.get_json(force=True, silent=True)
    if body is None or body == [] or body == {}:
        return jsonify({"error": "invalid or missing JSON body"}), 400
    batch = body if isinstance(body, list) else [body]
    now_us = time.time() * 1e6
    good = []
    for rec in batch:
        if not isinstance(rec, dict):
            continue
        rec.setdefault("kind", "unknown")
        rec.setdefault("received_at_us", now_us)
        good.append(rec)
    with _lock:
        _records.extend(good)
    try:
        with open(PERSIST_PATH, "a") as f:
            for rec in good:
                f.write(json.dumps(rec) + "\n")
    except Exception as e:
        app.logger.warning("Failed to persist context record: %s", e)
    return jsonify({"status": "ok", "stored": len(good)}), 201


def _snapshot():
    with _lock:
        return list(_records)


def _ts(r):
    return r.get("timestamp_us") or r.get("received_at_us") or 0


@app.route("/context", methods=["GET"])
def get_context():
    """
    Query params (all optional, ANDed): kind, ip (matches src_ip/dst_ip/ip),
    src_ip, dst_ip, src_port, dst_port, since_us, until_us, limit (default 50).
    Most-recent-first.
    """
    kind = request.args.get("kind")
    ip = request.args.get("ip")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    src_port = request.args.get("src_port", type=int)
    dst_port = request.args.get("dst_port", type=int)
    since = request.args.get("since_us", type=float)
    until = request.args.get("until_us", type=float)
    limit = request.args.get("limit", default=50, type=int)

    out = []
    for r in reversed(_snapshot()):
        if kind and r.get("kind") != kind:
            continue
        if ip and ip not in (r.get("src_ip"), r.get("dst_ip"), r.get("ip")):
            continue
        if src_ip and r.get("src_ip") != src_ip:
            continue
        if dst_ip and r.get("dst_ip") != dst_ip:
            continue
        if src_port is not None and r.get("src_port") != src_port:
            continue
        if dst_port is not None and r.get("dst_port") != dst_port:
            continue
        if since is not None and _ts(r) < since:
            continue
        if until is not None and _ts(r) > until:
            continue
        out.append(r)
        if len(out) >= limit:
            break
    return jsonify(out)


@app.route("/context/latest", methods=["GET"])
def get_latest():
    limit = request.args.get("limit", default=20, type=int)
    return jsonify(_snapshot()[-limit:][::-1])


@app.route("/assets", methods=["GET"])
def get_assets():
    return jsonify({"assets": ASSETS, "port_map": {str(k): v for k, v in PORT_MAP.items()},
                    "policy": POLICY})


# ---------------------------------------------------------------------------
# Enrichment: one call returns everything the LLM needs to describe a flow
# ---------------------------------------------------------------------------
def _kind(recs, kind, **eq):
    return [r for r in recs
            if r.get("kind") == kind and all(r.get(k) == v for k, v in eq.items())]


def _asset_label(ip):
    a = ASSETS.get(ip)
    return "%s (%s)" % (a["hostname"], a["type"]) if a else "%s (unknown asset)" % ip


def _expected_ports(asset):
    ports = set()
    for s in (asset or {}).get("expected_services", []):
        try:
            ports.add(int(s.split()[0].split("/")[1]))
        except Exception:
            pass
    return ports


@app.route("/enrich", methods=["GET"])
def enrich():
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    src_port = request.args.get("src_port", type=int)
    dst_port = request.args.get("dst_port", type=int)
    protocol = request.args.get("protocol", type=int)
    log_ts = request.args.get("log_ts_us", type=float)
    now_us = time.time() * 1e6

    # Per-flow detail that is intentionally NOT in flow_log.csv (fwd/bwd split, flags, conn_state...)
    detail = None
    if log_ts is not None:
        for r in reversed(_snapshot()):
            if (r.get("kind") == "flow_detail" and abs(_ts(r) - log_ts) <= 1000
                    and r.get("src_ip") == src_ip and r.get("dst_ip") == dst_ip
                    and (src_port is None or r.get("src_port") == src_port)):
                detail = r
                break
    if detail:
        start_us = detail["start_ts_us"]
        end_us = start_us + detail["duration_us"]
        dst_port = dst_port if dst_port is not None else detail.get("dst_port")
        protocol = protocol if protocol is not None else detail.get("protocol")
    else:
        start_us = request.args.get("start_us", type=float, default=now_us - 60e6)
        end_us = request.args.get("end_us", type=float, default=start_us)
    pre = request.args.get("pre_s", type=float, default=30.0) * 1e6
    post = request.args.get("post_s", type=float, default=10.0) * 1e6
    lo, hi = start_us - pre, end_us + post

    snap = _snapshot()
    win = [r for r in snap if lo <= _ts(r) <= hi]
    obs = []

    # assets --------------------------------------------------------------
    src_asset, dst_asset = ASSETS.get(src_ip), ASSETS.get(dst_ip)
    if src_ip:
        obs.append("Source %s." % _asset_label(src_ip))
    if dst_ip:
        obs.append("Destination %s, criticality %s." % (
            _asset_label(dst_ip), (dst_asset or {}).get("criticality", "unknown")))
    if dst_asset and dst_asset["type"] == "server" and dst_port is not None:
        exp = _expected_ports(dst_asset)
        if exp and dst_port not in exp:
            obs.append("Destination port %d is NOT one of the expected services of %s (%s)." % (
                dst_port, dst_asset["hostname"], ", ".join(dst_asset["expected_services"])))

    # per-flow detail -----------------------------------------------------------
    if detail:
        cs = detail.get("conn_state")
        meaning = {
            "EST": "The TCP handshake completed (SYN answered by SYN-ACK).",
            "REJ": "A SYN was answered with RST: the destination port is closed/rejected.",
            "S0": "A SYN was sent and the destination never answered.",
            "RST": "The flow was reset by the destination.",
            "NOREPLY": "The flow began with flags '%s' (not a normal SYN) and got no reply." % detail.get("fwd_first_flags"),
            "UDP_REPLY": "UDP request got a reply.",
            "UDP_NOREPLY": "UDP datagrams got no reply.",
            "ICMP_REPLY": "ICMP echo got a reply.",
            "ICMP_NOREPLY": "ICMP got no reply.",
        }.get(cs)
        if meaning:
            obs.append(meaning)
        obs.append("Direction split: %d packets / %d bytes forward, %d packets / %d bytes back." % (
            detail.get("fwd_packets", 0), detail.get("fwd_bytes", 0),
            detail.get("bwd_packets", 0), detail.get("bwd_bytes", 0)))
        if detail.get("bwd_packets", 0) == 0 and detail.get("fwd_packets", 0) >= 20:
            obs.append("One-sided flow: %d packets sent and nothing came back." % detail["fwd_packets"])

    # DNS -------------------------------------------------------------------
    dns_all = _kind(snap, "dns")
    dst_names = sorted({q for r in dns_all if r.get("is_response") and dst_ip in (r.get("answers") or [])
                        for q in (r.get("queries") or [])})
    resolved = [r for r in dns_all
                if r.get("is_response") and r.get("dst_ip") == src_ip
                and dst_ip in (r.get("answers") or [])
                and start_us - 120e6 <= _ts(r) <= start_us + 1e6]
    src_queries = sorted({q for r in dns_all
                          if r.get("src_ip") == src_ip and not r.get("is_response")
                          and lo <= _ts(r) <= hi for q in (r.get("queries") or [])})
    dns = {"dst_known_names": dst_names,
           "src_resolved_dst_before_flow": bool(resolved),
           "src_queries_in_window": src_queries[:20]}
    if dst_names:
        obs.append("Destination IP is known in DNS as: %s." % ", ".join(dst_names))
    if src_ip and dst_ip:
        obs.append("Source did resolve a name to the destination within 120 s before the flow."
                   if resolved else
                   "Source did NOT perform a DNS lookup for the destination in the 120 s before the flow.")

    # host behaviour (windowed) ----------------------------------------------------
    def activity(ip, key):
        acts = sorted(_kind(win, "host_activity", ip=ip), key=_ts)
        if not acts:
            return None
        return {"samples_in_window": len(acts), "peak": max(acts, key=lambda r: r.get(key, 0)),
                "latest": acts[-1]}

    src_act = activity(src_ip, "out_flows") if src_ip else None
    dst_act = activity(dst_ip, "in_flows") if dst_ip else None
    if src_act:
        p = src_act["peak"]
        obs.append("Source peak over a %ds window: %d new flows (%.1f/s) to %d distinct hosts and %d distinct ports; "
                   "%.0f%% of its TCP flows were bare SYNs; %d TCP flows began with non-SYN/ACK flags." % (
                       p.get("window_s", 30), p.get("out_flows", 0), p.get("out_flows_per_s", 0),
                       p.get("out_unique_dst_ips", 0), p.get("out_unique_dst_ports", 0),
                       100 * p.get("out_syn_only_ratio", 0), p.get("out_nonstandard_flag_flows", 0)))
        if p.get("out_rate_vs_baseline") is not None:
            obs.append("Source flow rate is %.1fx its own running baseline (%.2f flows/s)." % (
                p["out_rate_vs_baseline"], p.get("baseline_out_flows_per_s", 0)))
        elif p.get("host_age_s", 999) < 60:
            obs.append("Source has been seen on the network for only %.0f s (no behavioural history)." % p["host_age_s"])
    if dst_act:
        p = dst_act["peak"]
        obs.append("Destination peak inbound: %d new flows (%.1f/s) from %d distinct sources in %ds." % (
            p.get("in_flows", 0), p.get("in_flows_per_s", 0), p.get("in_unique_srcs", 0), p.get("window_s", 30)))

    # switch / link stats (core switch, dpid 1) -----------------------------
    ports = {}
    for r in _kind(win, "port_stats", dpid=1):
        for p in r.get("ports", []):
            a = ports.setdefault(p["port"], {"max_rx_Bps": 0, "max_tx_Bps": 0, "max_rx_pps": 0,
                                             "max_tx_pps": 0, "drops": 0, "errors": 0})
            a["max_rx_Bps"] = max(a["max_rx_Bps"], p.get("rx_Bps", 0))
            a["max_tx_Bps"] = max(a["max_tx_Bps"], p.get("tx_Bps", 0))
            a["max_rx_pps"] = max(a["max_rx_pps"], p.get("rx_pps", 0))
            a["max_tx_pps"] = max(a["max_tx_pps"], p.get("tx_pps", 0))
            a["drops"] += p.get("rx_dropped", 0) + p.get("tx_dropped", 0)
            a["errors"] += p.get("rx_errors", 0) + p.get("tx_errors", 0)
    link_rows = []
    for port, a in ports.items():
        a["peak_pps"] = round(max(a["max_rx_pps"], a["max_tx_pps"]), 1)
        a["peak_mbps"] = round(max(a["max_rx_Bps"], a["max_tx_Bps"]) * 8 / 1e6, 2)
        a["port"] = port
        a["attached"] = PORT_MAP.get(1, {}).get(port, "?")
        link_rows.append(a)
    link_rows.sort(key=lambda a: a["peak_pps"], reverse=True)
    tables = _kind(win, "table_stats", dpid=1)
    loads = _kind(win, "controller_load")
    switch = {"core_links": link_rows[:4],
              "max_active_flow_entries": max([t.get("active_flows", 0) for t in tables], default=None),
              "max_controller_packet_in_per_s": max([l.get("packet_in_per_s", 0) for l in loads], default=None)}
    if link_rows and link_rows[0]["peak_pps"] >= BUSY_LINK_PPS:
        a = link_rows[0]
        obs.append("Core link (%s) peaked at %.0f packets/s (%.1f Mbit/s) in the window." % (
            a["attached"], a["peak_pps"], a["peak_mbps"]))
    if switch["max_controller_packet_in_per_s"] and switch["max_controller_packet_in_per_s"] > 200:
        obs.append("Controller packet-in rate peaked at %.0f/s (unusually high new-flow load)." %
                   switch["max_controller_packet_in_per_s"])

    # service health of the destination -------------------------------------
    probes_win = [r for r in _kind(win, "service_probe") if r.get("target_ip") == dst_ip]
    probes_old = [r for r in _kind(snap, "service_probe")
                  if r.get("target_ip") == dst_ip and _ts(r) < lo and r.get("success")][-30:]
    health = None
    if probes_win:
        ok = [r["total_ms"] for r in probes_win if r.get("success") and "total_ms" in r]
        base = statistics.median([r["total_ms"] for r in probes_old if "total_ms" in r]) if probes_old else None
        health = {"probes": len(probes_win), "failures": len(probes_win) - len(ok),
                  "median_ms": round(statistics.median(ok), 1) if ok else None,
                  "max_ms": round(max(ok), 1) if ok else None,
                  "baseline_median_ms": round(base, 1) if base is not None else None}
        if health["failures"]:
            obs.append("%d of %d health probes to the destination failed in the window." % (
                health["failures"], health["probes"]))
        if base and health["max_ms"] and health["max_ms"] > 3 * max(base, 1.0):
            obs.append("Destination response time rose to %.0f ms (baseline ~%.0f ms)." % (health["max_ms"], base))

    # ARP bindings ----------------------------------------------------------
    arp_info = {}
    for ip in (src_ip, dst_ip):
        evs = [r for r in _kind(snap, "arp") if r.get("ip") == ip]
        if evs:
            arp_info[ip] = {"mac": evs[-1].get("mac"),
                            "changed_events": [r for r in evs if r.get("event") == "changed"][-3:]}
            if arp_info[ip]["changed_events"]:
                obs.append("The MAC address for %s changed (possible ARP spoofing or NIC replacement)." % ip)

    return jsonify({
        "flow": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                 "protocol": protocol, "start_us": start_us, "end_us": end_us},
        "flow_detail": detail,
        "window_us": [lo, hi],
        "assets": {"src": src_asset, "dst": dst_asset},
        "policy": POLICY,
        "dns": dns,
        "host_activity": {"src": src_act, "dst": dst_act},
        "switch": switch,
        "service_health": health,
        "arp": arp_info,
        "observations": obs,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
