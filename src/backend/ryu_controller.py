#!/usr/bin/env python3
import time
import csv
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp


MONITOR_INTERVAL = 5

# order matters: this is the column order a future ML model would expect
FEATURE_ORDER = [  
    "protocol", "src_port", "dst_port", "duration", "total_packets", "total_bytes", "packets_per_sec", "bytes_per_sec", "avg_packet_size",
]

CSV_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flow_log.csv")  
# always same folder as this script, regardless of cwd
CSV_COLUMNS = ["timestamp", "dpid", "src_ip", "dst_ip"] + FEATURE_ORDER


class FlowRecorder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowRecorder, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        if not os.path.exists(CSV_LOG_PATH):
            with open(CSV_LOG_PATH, "w", newline="") as f:
                csv.writer(f).writerow(CSV_COLUMNS)
        self.logger.info("Logging flow data to %s", CSV_LOG_PATH)

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        # table-miss rule: priority 0, matches everything, sends unmatched
        # packets to the controller. Without this, switches never talk to us.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                              actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match,
                                     instructions=inst,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=inst,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:

            # packet/byte counters correspond to one real network flow
            match = self._build_match(parser, in_port, eth, pkt, dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _build_match(self, parser, in_port, eth, pkt, dst):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return parser.OFPMatch(in_port=in_port, eth_dst=dst)  # non-IP (e.g. ARP): plain L2 match, no 5-tuple possible

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        match_fields = dict(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=ip_pkt.proto,
        )
        if tcp_pkt is not None:
            match_fields["tcp_src"] = tcp_pkt.src_port
            match_fields["tcp_dst"] = tcp_pkt.dst_port
        elif udp_pkt is not None:
            match_fields["udp_src"] = udp_pkt.src_port
            match_fields["udp_dst"] = udp_pkt.dst_port

        return parser.OFPMatch(**match_fields)

    def _monitor(self):
        # background loop: asks every connected switch for flow stats
        # every MONITOR_INTERVAL seconds, for as long as the controller runs
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        for stat in ev.msg.body:
            match = stat.match

            if match.get("eth_type") != ether_types.ETH_TYPE_IP:
                continue  # skip the table-miss rule and non-IP entries (e.g. ARP)
            if stat.packet_count == 0:
                continue  # nothing happened on this flow yet

            features = self._extract_features(stat)
            if features is None:
                continue

            self._log_to_csv(dpid, match, features)

    def _extract_features(self, stat):
        match = stat.match
        try:
            proto = match.get("ip_proto")
            src_port = match.get("tcp_src", match.get("udp_src", 0))
            dst_port = match.get("tcp_dst", match.get("udp_dst", 0))

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            duration = max(duration, 0.001)  # guard against divide-by-zero on brand-new flows

            total_packets = stat.packet_count
            total_bytes = stat.byte_count
            packets_per_sec = total_packets / duration
            bytes_per_sec = total_bytes / duration
            avg_packet_size = total_bytes / max(total_packets, 1)

            return {
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "duration": duration,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "packets_per_sec": packets_per_sec,
                "bytes_per_sec": bytes_per_sec,
                "avg_packet_size": avg_packet_size,
            }
        except Exception as e:
            self.logger.debug("Feature extraction failed: %s", e)
            return None

    def _log_to_csv(self, dpid, match, features):
        row = {
            "timestamp": time.time(),
            "dpid": dpid,
            "src_ip": match.get("ipv4_src"),
            "dst_ip": match.get("ipv4_dst"),
        }
        row.update(features)

        try:
            with open(CSV_LOG_PATH, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writerow(row)
        except Exception as e:
            self.logger.error("Failed to write CSV row: %s", e)
