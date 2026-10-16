#!/usr/bin/env python3
"""
RYU controller: forwarding + flow recording + context collection.

What it writes
--------------
flow_log.csv
one row per *bidirectional* conversation (forward and reverse OpenFlow entries are merged),
ONLY the original columns (protocol, ports, duration, packets, bytes, rates, avg size, label).
Rows are written in time order, and only for the labels normal / portscan / dos (traffic from
any other host is not logged). This is the final dataset; there is no separate "full" log.

What it pushes to the context API (context_api.py)
--------------------------------------------------
dns, arp, host_activity (per-IP behaviour over a sliding window), port_stats,
table_stats, controller_load, and flow_detail (per-flow extras that are NOT in the CSV:
forward/backward split, first-packet flags, connection state, host context at log time).
"""
import csv
import os
import time
from collections import Counter, defaultdict, deque

import requests
import dns.message
import dns.flags
import dns.rcode

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp, arp


IDLE_TIMEOUT = 10      # seconds with no packets before a flow times out and gets logged
HARD_TIMEOUT = 60      # seconds: long flows (like slowloris) get cut off here and logged in pieces
PAIR_WAIT = 5          # seconds to wait for the reverse direction before logging a one-way flow
ACTIVITY_WINDOW = 30   # seconds: sliding window for per-host behaviour stats
ACTIVITY_INTERVAL = 5  # seconds between host_activity snapshots
STATS_INTERVAL = 5     # seconds between port/table stats polls
BASELINE_ALPHA = 0.05  # EWMA weight for each host's flow-rate baseline (small, so the baseline moves slowly)
CONTEXT_API_URL = "http://127.0.0.1:5001/context"

# ---- original columns (same names and order as before, so the teammate's pipeline still works) ----
FEATURE_ORDER = [
    "protocol", "src_port", "dst_port", "duration_us", "total_packets",
    "total_bytes", "packets_per_sec", "bytes_per_sec", "avg_packet_size",
]
# Everything else about a flow (fwd/bwd split, flags, conn_state, host context) doesn't go in the CSV.
# It's sent to the context API as kind=flow_detail instead.
CSV_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flow_log.csv")
CSV_COLUMNS = ["timestamp_us", "dpid", "src_ip", "dst_ip"] + FEATURE_ORDER + ["label"]

# Ground-truth labels, based on which host the traffic came from. Matches THE-TOPOLOGY.py.
DOS_IPS = {"10.0.0.10"}                       # h_atk
SCAN_IPS = {"10.0.0.13"}                      # h_scan
NORMAL_IPS = {"10.0.0.11", "10.0.0.12"}       # h_user1, h_user2
# anything else is labelled "other" and left out of the final dataset

# Every switch on a flow's path sees it, and every flow goes through s1 (the core),
# so we only log at s1. Otherwise each flow would be logged once per switch.
LOG_ONLY_DPID = 1


def label_flow(src_ip, dst_ip):
    """Label by host role; checks both directions so reply traffic gets the same label."""
    ends = {src_ip, dst_ip}
    if ends & DOS_IPS:
        return "dos"
    if ends & SCAN_IPS:
        return "portscan"
    if ends & NORMAL_IPS:
        return "normal"
    return "other"


def flags_str(bits):
    s = "".join(ch for mask, ch in ((0x01, "F"), (0x02, "S"), (0x04, "R"),
                                    (0x08, "P"), (0x10, "A"), (0x20, "U")) if bits & mask)
    return s or "none"


def conn_state(proto, fflags, bflags, has_bwd):
    """Zeek-like heuristic from first-packet flags of each direction."""
    if proto == 6:
        if not has_bwd:
            return "S0" if fflags == "S" else "NOREPLY"
        if "R" in bflags:
            return "REJ" if fflags == "S" else "RST"
        if bflags == "SA" and fflags == "S":
            return "EST"
        return "OTH"
    if proto == 17:
        return "UDP_REPLY" if has_bwd else "UDP_NOREPLY"
    if proto == 1:
        return "ICMP_REPLY" if has_bwd else "ICMP_NOREPLY"
    return "OTH"


class FlowRecorder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowRecorder, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_meta = {}            # 5-tuple -> {"flags", "t"}, taken from the first packet
        self.pending = {}              # canonical key -> half-flow waiting for the reverse direction
        self.ip_mac = {}               # ip -> (mac, dpid, port)
        self.first_seen = {}
        self.out_events = defaultdict(deque)   # src_ip -> (t, dst_ip, proto, dst_port, flags)
        self.in_events = defaultdict(deque)    # dst_ip -> (t, src_ip)
        self.rate_baseline = {}
        self.activity_latest = {}
        self.prev_port_stats = {}
        self.counters = defaultdict(int)
        self._last_counters = defaultdict(int)
        self._last_load_t = time.time()
        self.seen_rows = set()
        self.detail_queue = []
        self.rows_logged = defaultdict(int)

        self._init_csv()
        self.logger.info("Logging flow data to %s", CSV_LOG_PATH)
        hub.spawn(self._pair_flush_loop)
        hub.spawn(self._activity_loop)
        hub.spawn(self._stats_loop)

    def _init_csv(self):
        expected = ",".join(CSV_COLUMNS)
        if os.path.exists(CSV_LOG_PATH) and os.path.getsize(CSV_LOG_PATH) > 0:
            with open(CSV_LOG_PATH) as f:
                first = f.readline().strip()
            if first != expected:
                backup = "%s.old-%d" % (CSV_LOG_PATH, int(time.time()))
                os.rename(CSV_LOG_PATH, backup)
                self.logger.warning("Existing log had a different header; moved to %s", backup)
        if not os.path.exists(CSV_LOG_PATH) or os.path.getsize(CSV_LOG_PATH) == 0:
            with open(CSV_LOG_PATH, "w", newline="") as f:
                csv.writer(f).writerow(CSV_COLUMNS)

    # switch setup -------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # SEND_FLOW_REM makes the switch send us the final stats when a flow times out.
        flags = ofproto.OFPFF_SEND_FLOW_REM if (idle_timeout or hard_timeout) else 0
        kwargs = dict(datapath=datapath, priority=priority, match=match, instructions=inst,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
        if buffer_id:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    # packet-in ----------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']
        self.counters["packet_in"] += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            self._track_arp(dpid, in_port, arp_pkt)

        # Only capture DNS at the logging switch. Otherwise every packet gets
        # recorded once for each switch it goes through.
        if LOG_ONLY_DPID is None or dpid == LOG_ONLY_DPID:
            self._maybe_capture_dns(pkt)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = self._build_match(parser, in_port, eth, pkt, dst)
            self.add_flow(datapath, 1, match, actions,
                          idle_timeout=IDLE_TIMEOUT, hard_timeout=HARD_TIMEOUT)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt is not None and (LOG_ONLY_DPID is None or dpid == LOG_ONLY_DPID):
                self._track_new_flow(pkt, ip_pkt)
            # Send the packet back through the table so the new entry counts the first packet too.
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _build_match(self, parser, in_port, eth, pkt, dst):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            # eth_type is part of the match so an ARP entry can't also match IP traffic with the
            # same in_port/eth_dst. If it did, the controller would never see those flows.
            return parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_dst=dst)

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        fields = dict(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                      ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, ip_proto=ip_pkt.proto)
        if tcp_pkt is not None:
            fields["tcp_src"] = tcp_pkt.src_port
            fields["tcp_dst"] = tcp_pkt.dst_port
        elif udp_pkt is not None:
            fields["udp_src"] = udp_pkt.src_port
            fields["udp_dst"] = udp_pkt.dst_port
        elif icmp_pkt is not None:
            fields["icmpv4_type"] = icmp_pkt.type
            fields["icmpv4_code"] = icmp_pkt.code
        return parser.OFPMatch(**fields)

    # context: new-flow tracking -----------------------------------------

    def _track_new_flow(self, pkt, ip_pkt):
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        sport = dport = 0
        flags = ""
        if tcp_pkt is not None:
            sport, dport, flags = tcp_pkt.src_port, tcp_pkt.dst_port, flags_str(tcp_pkt.bits)
        elif udp_pkt is not None:
            sport, dport = udp_pkt.src_port, udp_pkt.dst_port
        elif icmp_pkt is not None:
            flags = "icmp%d" % icmp_pkt.type
        now = time.time()
        key5 = (ip_pkt.src, ip_pkt.dst, ip_pkt.proto, sport, dport)
        self.flow_meta[key5] = {"flags": flags, "t": now}
        self.out_events[ip_pkt.src].append((now, ip_pkt.dst, ip_pkt.proto, dport, flags))
        self.in_events[ip_pkt.dst].append((now, ip_pkt.src))
        self.first_seen.setdefault(ip_pkt.src, now)
        self.first_seen.setdefault(ip_pkt.dst, now)

    def _track_arp(self, dpid, in_port, a):
        ip, mac = a.src_ip, a.src_mac
        if not ip or ip == "0.0.0.0":
            return
        prev = self.ip_mac.get(ip)
        if prev is not None and prev[0] == mac:
            return
        self.ip_mac[ip] = (mac, dpid, in_port)
        self._post_context([{
            "kind": "arp", "timestamp_us": time.time() * 1e6, "ip": ip, "mac": mac,
            "dpid": dpid, "port": in_port,
            "event": "new" if prev is None else "changed",
            "previous_mac": prev[0] if prev else None,
        }])

    def _maybe_capture_dns(self, pkt):
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt is None or (udp_pkt.src_port != 53 and udp_pkt.dst_port != 53):
            return
        payload = pkt.protocols[-1]
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            return
        try:
            dns_msg = dns.message.from_wire(bytes(payload))
        except Exception:
            return
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        record = {
            "kind": "dns",
            "timestamp_us": time.time() * 1e6,
            "src_ip": ip_pkt.src if ip_pkt else None,
            "dst_ip": ip_pkt.dst if ip_pkt else None,
            "src_port": udp_pkt.src_port,
            "dst_port": udp_pkt.dst_port,
            "is_response": bool(dns_msg.flags & dns.flags.QR),
            "rcode": dns.rcode.to_text(dns_msg.rcode()),
            "queries": [q.name.to_text(omit_final_dot=True) for q in dns_msg.question],
            "answers": [rd.to_text() for rr in dns_msg.answer for rd in rr],
        }
        self._post_context([record])

    def _post_context(self, records):
        hub.spawn(self._post_context_blocking, records)

    def _post_context_blocking(self, records):
        try:
            requests.post(CONTEXT_API_URL, json=records, timeout=1)
        except Exception as e:
            self.logger.debug("Context API push failed: %s", e)

    # context: periodic loops --------------------------------------------

    def _activity_loop(self):
        while True:
            hub.sleep(ACTIVITY_INTERVAL)
            try:
                self._publish_activity()
            except Exception as e:
                self.logger.warning("activity snapshot failed: %s", e)

    def _publish_activity(self):
        now = time.time()
        cutoff = now - ACTIVITY_WINDOW
        latest, records = {}, []
        for ip in set(self.out_events) | set(self.in_events):
            ev, iev = self.out_events.get(ip, deque()), self.in_events.get(ip, deque())
            while ev and ev[0][0] < cutoff:
                ev.popleft()
            while iev and iev[0][0] < cutoff:
                iev.popleft()
            if not ev and not iev:
                self.out_events.pop(ip, None)
                self.in_events.pop(ip, None)
                continue
            n = len(ev)
            tcp_n = sum(1 for e in ev if e[2] == 6)
            syn_only = sum(1 for e in ev if e[2] == 6 and e[4] == "S")
            nonstd = sum(1 for e in ev if e[2] == 6 and "S" not in e[4] and "A" not in e[4])
            top = Counter(e[3] for e in ev if e[3]).most_common(1)
            rate = n / float(ACTIVITY_WINDOW)
            base = self.rate_baseline.get(ip)
            ratio = (rate / max(base, 0.05)) if base is not None else None
            self.rate_baseline[ip] = rate if base is None else \
                base * (1 - BASELINE_ALPHA) + min(rate, base * 3 + 0.05) * BASELINE_ALPHA
            snap = {
                "kind": "host_activity", "timestamp_us": now * 1e6, "dpid": LOG_ONLY_DPID,
                "ip": ip, "window_s": ACTIVITY_WINDOW,
                "out_flows": n, "out_flows_per_s": round(rate, 3),
                "out_unique_dst_ips": len({e[1] for e in ev}),
                "out_unique_dst_ports": len({e[3] for e in ev if e[3]}),
                "out_syn_only_ratio": round(syn_only / tcp_n, 3) if tcp_n else 0.0,
                "out_nonstandard_flag_flows": nonstd,
                "out_udp_flows": sum(1 for e in ev if e[2] == 17),
                "out_icmp_flows": sum(1 for e in ev if e[2] == 1),
                "out_top_dst_port": top[0][0] if top else None,
                "in_flows": len(iev), "in_flows_per_s": round(len(iev) / float(ACTIVITY_WINDOW), 3),
                "in_unique_srcs": len({e[1] for e in iev}),
                "baseline_out_flows_per_s": round(base, 3) if base is not None else None,
                "out_rate_vs_baseline": round(ratio, 2) if ratio is not None else None,
                "host_age_s": round(now - self.first_seen.get(ip, now), 1),
            }
            latest[ip] = snap
            records.append(snap)
        self.activity_latest = latest
        for k in [k for k, v in self.flow_meta.items() if now - v["t"] > 300]:
            del self.flow_meta[k]
        if records:
            self._post_context(records)

    def _stats_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            for dp in list(self.datapaths.values()):
                try:
                    parser = dp.ofproto_parser
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
                    dp.send_msg(parser.OFPTableStatsRequest(dp, 0))
                except Exception as e:
                    self.logger.debug("stats request failed: %s", e)
            now = time.time()
            dt = max(now - self._last_load_t, 1e-3)
            self._post_context([{
                "kind": "controller_load", "timestamp_us": now * 1e6,
                "packet_in_per_s": round((self.counters["packet_in"] - self._last_counters["packet_in"]) / dt, 2),
                "flow_removed_per_s": round((self.counters["flow_removed"] - self._last_counters["flow_removed"]) / dt, 2),
                "pending_pairs": len(self.pending),
            }])
            self._last_counters = defaultdict(int, self.counters)
            self._last_load_t = now

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid, now, ports = ev.msg.datapath.id, time.time(), []
        for st in ev.msg.body:
            if st.port_no >= 0xffffff00:      # skip the LOCAL and other special ports
                continue
            cur = (st.rx_packets, st.tx_packets, st.rx_bytes, st.tx_bytes,
                   st.rx_dropped, st.tx_dropped, st.rx_errors, st.tx_errors)
            prev = self.prev_port_stats.get((dpid, st.port_no))
            self.prev_port_stats[(dpid, st.port_no)] = (now, cur)
            if prev is None:
                continue
            dt = max(now - prev[0], 1e-3)
            d = [max(0, c - p) for c, p in zip(cur, prev[1])]
            ports.append({"port": st.port_no, "rx_pps": round(d[0] / dt, 1), "tx_pps": round(d[1] / dt, 1),
                          "rx_Bps": round(d[2] / dt, 1), "tx_Bps": round(d[3] / dt, 1),
                          "rx_dropped": d[4], "tx_dropped": d[5], "rx_errors": d[6], "tx_errors": d[7]})
        if ports:
            self._post_context([{"kind": "port_stats", "timestamp_us": now * 1e6,
                                 "dpid": dpid, "ports": ports}])

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        for t in ev.msg.body:
            if t.table_id == 0:
                self._post_context([{"kind": "table_stats", "timestamp_us": time.time() * 1e6,
                                     "dpid": ev.msg.datapath.id, "active_flows": t.active_count,
                                     "lookups": t.lookup_count, "matched": t.matched_count}])

    # flow completion -> bidirectional rows ------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match
        if match.get("eth_type") != ether_types.ETH_TYPE_IP:
            return
        if msg.packet_count == 0:
            return
        if LOG_ONLY_DPID is not None and msg.datapath.id != LOG_ONLY_DPID:
            return
        self.counters["flow_removed"] += 1

        # The duration includes the idle time at the end of a timed-out flow, so subtract it.
        idle_offset = IDLE_TIMEOUT if msg.reason == msg.datapath.ofproto.OFPRR_IDLE_TIMEOUT else 0
        half = self._make_half(msg, idle_offset)
        if half is not None:
            self._pair_or_hold(half)

    def _make_half(self, msg, idle_offset):
        try:
            match = msg.match
            now = time.time()
            src, dst = match.get("ipv4_src"), match.get("ipv4_dst")
            proto = match.get("ip_proto")
            sport = match.get("tcp_src", match.get("udp_src", 0))
            dport = match.get("tcp_dst", match.get("udp_dst", 0))
            meta = self.flow_meta.pop((src, dst, proto, sport, dport), None) or {}
            full = msg.duration_sec + msg.duration_nsec / 1e9
            return {"dpid": msg.datapath.id, "src": src, "dst": dst, "proto": proto,
                    "sport": sport, "dport": dport,
                    "pkts": msg.packet_count, "bytes": msg.byte_count,
                    "dur": max(full - idle_offset, 0.001),
                    "start": meta.get("t", now - full), "flags": meta.get("flags", ""),
                    "deadline": now + PAIR_WAIT}
        except Exception as e:
            self.logger.debug("half-flow extraction failed: %s", e)
            return None

    def _pair_or_hold(self, half):
        a, b = (half["src"], half["sport"]), (half["dst"], half["dport"])
        key = (half["proto"],) + tuple(sorted([a, b]))
        held = self.pending.get(key)
        if held is not None:
            if held["src"] == half["dst"] and held["dst"] == half["src"]:
                del self.pending[key]
                self._emit_row(held, half)
                return
            del self.pending[key]               # same direction again: log the older one and hold the new one
            self._emit_row(held, None)
        self.pending[key] = half

    def _pair_flush_loop(self):
        while True:
            hub.sleep(1)
            now = time.time()
            for key in [k for k, h in self.pending.items() if h["deadline"] <= now]:
                self._emit_row(self.pending.pop(key), None)
            if self.detail_queue:
                batch, self.detail_queue = self.detail_queue, []
                self._post_context(batch)

    def _emit_row(self, fwd, bwd):
        if bwd is not None and bwd["start"] < fwd["start"]:
            fwd, bwd = bwd, fwd                  # the side that sent its first packet first is the initiator
        fp, fb = fwd["pkts"], fwd["bytes"]
        bp = bwd["pkts"] if bwd else 0
        bb = bwd["bytes"] if bwd else 0
        dur = max(fwd["dur"], bwd["dur"] if bwd else 0.0, 0.001)
        total_p, total_b = fp + bp, fb + bb
        bflags = bwd["flags"] if bwd else ""
        ts_us = time.time() * 1e6

        # ---- the CSV row (original columns only) ----
        row = {
            "timestamp_us": ts_us, "dpid": fwd["dpid"],
            "src_ip": fwd["src"], "dst_ip": fwd["dst"],
            "protocol": fwd["proto"], "src_port": fwd["sport"], "dst_port": fwd["dport"],
            "duration_us": dur * 1e6, "total_packets": total_p, "total_bytes": total_b,
            "packets_per_sec": total_p / dur, "bytes_per_sec": total_b / dur,
            "avg_packet_size": total_b / max(total_p, 1),
            "label": label_flow(fwd["src"], fwd["dst"]),
        }
        if row["label"] == "other":
            return                               # only normal / portscan / dos belong in the dataset
        if not self._log_to_csv(row, fwd["start"] * 1e6):
            return

        # ---- everything that's not in the CSV goes to the context API ----
        # Matches up with the CSV row by (timestamp_us, src_ip, dst_ip, src_port, dst_port). No label here.
        cs, cd = self.activity_latest.get(fwd["src"], {}), self.activity_latest.get(fwd["dst"], {})
        self.detail_queue.append({
            "kind": "flow_detail", "timestamp_us": ts_us,
            "src_ip": fwd["src"], "dst_ip": fwd["dst"], "protocol": fwd["proto"],
            "src_port": fwd["sport"], "dst_port": fwd["dport"],
            "start_ts_us": fwd["start"] * 1e6, "duration_us": dur * 1e6,
            "fwd_packets": fp, "bwd_packets": bp, "fwd_bytes": fb, "bwd_bytes": bb,
            "fwd_avg_pkt_size": round(fb / max(fp, 1), 1),
            "bwd_avg_pkt_size": round(bb / bp, 1) if bp else 0,
            "fwd_first_flags": fwd["flags"], "bwd_first_flags": bflags,
            "conn_state": conn_state(fwd["proto"], fwd["flags"], bflags, bwd is not None),
            "src_flows_30s": cs.get("out_flows", 0),
            "src_unique_dst_ports_30s": cs.get("out_unique_dst_ports", 0),
            "src_unique_dst_ips_30s": cs.get("out_unique_dst_ips", 0),
            "src_syn_only_ratio_30s": cs.get("out_syn_only_ratio", 0),
            "dst_flows_30s": cd.get("in_flows", 0),
            "dst_unique_srcs_30s": cd.get("in_unique_srcs", 0),
        })

    def _log_to_csv(self, row, start_ts_us):
        """Returns True if the row was written."""
        # If the CSV got deleted while this was running, start a new one.
        if not os.path.exists(CSV_LOG_PATH) or os.path.getsize(CSV_LOG_PATH) == 0:
            self.seen_rows.clear()
            self.rows_logged.clear()
            with open(CSV_LOG_PATH, "w", newline="") as f:
                csv.writer(f).writerow(CSV_COLUMNS)

        key = (row["src_ip"], row["dst_ip"], row["protocol"], row["src_port"],
               row["dst_port"], round(start_ts_us / 1000.0))
        if key in self.seen_rows:
            return False
        try:
            with open(CSV_LOG_PATH, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow(row)
        except Exception as e:
            self.logger.error("Failed to write CSV row: %s", e)
            return False
        self.seen_rows.add(key)
        label = row["label"]
        self.rows_logged[label] += 1
        if self.rows_logged[label] % 500 == 0:
            self.logger.info("rows logged so far: %s", dict(self.rows_logged))
        return True
