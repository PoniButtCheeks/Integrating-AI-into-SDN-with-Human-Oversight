# Network capture v2

Generated 16 October 2026 on the project mini PC with src/backend/traffic_gen.py, called as run_scenario(net, seed=1), and src/backend/ryu_controller.py.

## Design
6 runs of 15 minutes with a 150 s idle gap between runs. Benign background traffic runs for the whole of each run. Attack episodes start at random times, never in the first 60 s or the last 120 s of a run. Target about 90% normal.

## Result
13,188 flows: normal 11,986 (90.9%), portscan 601 (4.6%), dos 601 (4.6%).

## Files
- flow_log.csv: one row per bidirectional flow, logged at the core switch s1. Columns: timestamp_us, dpid, src_ip, dst_ip, protocol, src_port, dst_port, duration_us, total_packets, total_bytes, packets_per_sec, bytes_per_sec, avg_packet_size, label. Labels come from the source host and are for evaluation only.
- scenario_windows.csv: 48 windows. 6 "normal, background" rows, one per run, covering the whole run, plus 42 attack episodes with technique, source host, target and start and end time.
- context_log.jsonl: every record posted to the context API (dns, arp, host_activity, port_stats, table_stats, controller_load, flow_detail, service_probe).

## Assigning rows to runs
timestamp_us is when the row was written, after the flow ended. A row belongs to the run whose background window contains its timestamp_us. Check that no rows are left unassigned.

## Known properties to account for in evaluation
- src_ip gives the label away exactly (10.0.0.13 is always portscan, 10.0.0.10 is always dos). Do not use it as a feature.
- Normal traffic only uses destination ports 80, 443 and 53 plus ICMP, so dst_port is partly a label giveaway in this lab.
- About 30% of non-connect scans use --data-length padding. The rest are unpadded, like the demo scan.
- DoS traffic comes from a single host (h_atk), so it is DoS, not distributed DoS.

Code version: e0be2fdae2fbf5b7f8b69456ea5068d3b1ce0e85
