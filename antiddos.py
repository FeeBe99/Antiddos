#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          Anti-DDoS 4-Layer Defense Architecture                      ║
║  Layer 1 : XDP/eBPF      — driver-level, ~100 ns                    ║
║  Layer 2 : iptables mangle — pre-routing scrub                       ║
║  Layer 3 : ipset hash:ip  — O(1) million-IP blacklist                ║
║  Layer 4 : Application chains — flood guards                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR       = Path("/etc/antiddos")
WHITELIST_FILE = BASE_DIR / "whitelist.conf"
BLACKLIST_FILE = BASE_DIR / "blacklist.conf"
XDP_OBJ        = BASE_DIR / "xdp_filter.o"
XDP_SRC        = Path(__file__).parent / "xdp_filter.c"
STATE_FILE     = BASE_DIR / "state.json"
LOG_FILE       = BASE_DIR / "antiddos.log"

# ─── Discord Webhook ─────────────────────────────────────────────────────────
# Paste your Discord webhook URL here:
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1485639631876653066/cE_eP2D5kxASTPSivMHkyX6shhdULX4ThmadIWdLrFBkTtS5q9yx5BefCWrZRhx-wHsr"

# Cooldown in seconds between alerts of the same type (avoids spam)
DISCORD_COOLDOWN = 60   # 1 alert per attack type per minute max

# ─── Colours ──────────────────────────────────────────────────────────────────

R  = "\033[91m";  G  = "\033[92m";  Y  = "\033[93m"
B  = "\033[94m";  C  = "\033[96m";  W  = "\033[97m"
DIM = "\033[2m";  BOLD = "\033[1m"; NC = "\033[0m"

def banner():
    print(f"""{B}{BOLD}
 ╔══════════════════════════════════════════════════════════════╗
 ║  ░█████╗░███╗░░██╗████████╗██╗██████╗░██████╗░░█████╗░░██████╗  ║
 ║     Anti-DDoS 4-Layer Defense  ·  v2.0                      ║
 ╚══════════════════════════════════════════════════════════════╝{NC}
""")

def log(level: str, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    colour = {
        "INFO":  G, "WARN": Y, "ERROR": R, "DEBUG": DIM
    }.get(level, W)
    print(f"  {colour}[{level}]{NC} {msg}")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass

# ─── Discord Notifier ────────────────────────────────────────────────────────

class DiscordNotifier:
    """
    Sends threshold-based attack alerts to a Discord webhook.
    Each alert type has its own cooldown so you don't get flooded
    with messages during a sustained attack.
    """

    # Embed colours (Discord decimal)
    _COLORS = {
        "syn":       0xe74c3c,   # red
        "udp":       0xe67e22,   # orange
        "icmp":      0xf1c40f,   # yellow
        "blacklist": 0x9b59b6,   # purple
    }

    # Minimum drops-per-second delta to consider it an "attack"
    # (compares two consecutive iptables snapshots 10 s apart)
    THRESHOLDS = {
        "syn":       50,    # SYN drops/s
        "udp":       200,   # UDP drops/s
        "icmp":      20,    # ICMP drops/s
        "blacklist": 1,     # any blacklist hit counts
    }

    def __init__(self, webhook_url: str, cooldown: int = 60):
        self.webhook_url = webhook_url
        self.cooldown    = cooldown
        self._last_sent: dict[str, float] = {}

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _ready(self, key: str) -> bool:
        """Return True if cooldown has elapsed for this alert type."""
        now = time.time()
        if now - self._last_sent.get(key, 0) >= self.cooldown:
            self._last_sent[key] = now
            return True
        return False

    def _send(self, payload: dict):
        """Fire-and-forget POST to Discord in a daemon thread."""
        if not self.webhook_url or self.webhook_url == "YOUR_WEBHOOK_URL_HERE":
            return

        def _post():
            try:
                data = json.dumps(payload).encode()
                req  = urllib.request.Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as exc:
                log("WARN", f"Discord webhook failed: {exc}")

        t = threading.Thread(target=_post, daemon=True)
        t.start()

    def _embed(self, title: str, description: str,
               color: int, fields: list[dict]) -> dict:
        return {
            "embeds": [{
                "title":       title,
                "description": description,
                "color":       color,
                "fields":      fields,
                "footer":      {"text": "Anti-DDoS · " + time.strftime("%Y-%m-%d %H:%M:%S")},
            }]
        }

    # ── Public alert methods ─────────────────────────────────────────────────

    def alert_syn_flood(self, drops_per_sec: float, src_ip: str = ""):
        if not self._ready("syn"):
            return
        fields = [{"name": "Drop rate", "value": f"`{drops_per_sec:.0f}` SYN/s", "inline": True}]
        if src_ip:
            fields.append({"name": "Top source", "value": f"`{src_ip}`", "inline": True})
        self._send(self._embed(
            "🚨 SYN Flood Detected",
            "Incoming SYN flood is exceeding the drop threshold.",
            self._COLORS["syn"], fields,
        ))
        log("INFO", f"Discord: SYN flood alert sent ({drops_per_sec:.0f}/s)")

    def alert_udp_flood(self, drops_per_sec: float, src_ip: str = ""):
        if not self._ready("udp"):
            return
        fields = [{"name": "Drop rate", "value": f"`{drops_per_sec:.0f}` UDP/s", "inline": True}]
        if src_ip:
            fields.append({"name": "Top source", "value": f"`{src_ip}`", "inline": True})
        self._send(self._embed(
            "🚨 UDP Flood Detected",
            "Incoming UDP flood is exceeding the drop threshold.",
            self._COLORS["udp"], fields,
        ))
        log("INFO", f"Discord: UDP flood alert sent ({drops_per_sec:.0f}/s)")

    def alert_icmp_flood(self, drops_per_sec: float, src_ip: str = ""):
        if not self._ready("icmp"):
            return
        fields = [{"name": "Drop rate", "value": f"`{drops_per_sec:.0f}` ICMP/s", "inline": True}]
        if src_ip:
            fields.append({"name": "Top source", "value": f"`{src_ip}`", "inline": True})
        self._send(self._embed(
            "🚨 ICMP Flood Detected",
            "Incoming ICMP flood is exceeding the drop threshold.",
            self._COLORS["icmp"], fields,
        ))
        log("INFO", f"Discord: ICMP flood alert sent ({drops_per_sec:.0f}/s)")

    def alert_blacklist(self, ip: str):
        # Her IP için ayrı cooldown key'i kullan — farklı IP'ler birbirini susturmaz
        if not self._ready(f"blacklist:{ip}"):
            return
        self._send(self._embed(
            "🛡️ IP Blacklisted",
            "An IP was added to the active blacklist.",
            self._COLORS["blacklist"],
            [{"name": "Blocked IP", "value": f"`{ip}`", "inline": True}],
        ))
        log("INFO", f"Discord: blacklist alert sent for {ip}")


# ─── Attack Monitor (background thread) ──────────────────────────────────────

class AttackMonitor:
    """
    Runs as a background daemon thread while protection is active.
    Polls iptables drop counters every POLL_INTERVAL seconds and
    fires Discord alerts when drops/s exceed configured thresholds.
    """

    POLL_INTERVAL = 10   # seconds between iptables snapshots

    # Maps iptables chain names → notifier method + threshold key
    CHAIN_MAP = {
        "syn_flood":    ("syn",  "alert_syn_flood"),
        "udp_generic":  ("udp",  "alert_udp_flood"),
        "icmp_guard":   ("icmp", "alert_icmp_flood"),
    }

    def __init__(self, notifier: DiscordNotifier):
        self.notifier  = notifier
        self._stop_evt = threading.Event()
        self._thread   = threading.Thread(target=self._loop, daemon=False, name="AttackMonitor")
        self._prev: dict[str, int] = {}

    def start(self):
        self._thread.start()
        log("INFO", "Attack monitor started (Discord alerts enabled).")

    def stop(self):
        self._stop_evt.set()

    # ── Internals ────────────────────────────────────────────────────────────

    def _get_hashlimit_drops(self) -> dict[str, int]:
        """
        Read per-hashlimit-name drop counters from
        /proc/net/ipt_hashlimit/<name> (packet count field).
        Falls back to zero if the file isn't there.
        """
        drops: dict[str, int] = {}
        base = Path("/proc/net/ipt_hashlimit")
        if not base.exists():
            return drops
        for name in ["syn_flood", "ack_flood", "rst_flood",
                     "udp_dns", "udp_generic", "icmp_guard"]:
            p = base / name
            if p.exists():
                try:
                    total = 0
                    for line in p.read_text().splitlines()[1:]:  # skip header
                        cols = line.split()
                        if len(cols) >= 3:
                            total += int(cols[2])  # packets column (index 2)
                    drops[name] = total
                except Exception:
                    drops[name] = 0
        return drops

    def _loop(self):
        while not self._stop_evt.wait(self.POLL_INTERVAL):
            curr = self._get_hashlimit_drops()

            for hl_name, (thresh_key, method_name) in self.CHAIN_MAP.items():
                curr_val = curr.get(hl_name, 0)
                prev_val = self._prev.get(hl_name, curr_val)
                delta    = max(0, curr_val - prev_val)
                dps      = delta / self.POLL_INTERVAL

                threshold = DiscordNotifier.THRESHOLDS[thresh_key]
                if dps >= threshold:
                    getattr(self.notifier, method_name)(dps)

            self._prev = curr


# Singleton instances — created when protection starts
_notifier: DiscordNotifier | None = None
_attack_monitor: AttackMonitor | None = None


def start_attack_monitor():
    global _notifier, _attack_monitor
    _notifier = DiscordNotifier(DISCORD_WEBHOOK_URL, cooldown=DISCORD_COOLDOWN)
    _attack_monitor = AttackMonitor(_notifier)
    _attack_monitor.start()
    if DISCORD_WEBHOOK_URL == "YOUR_WEBHOOK_URL_HERE":
        log("WARN", "Discord webhook URL not set — attack alerts disabled.")
    else:
        log("INFO", f"Discord alerts active (cooldown={DISCORD_COOLDOWN}s).")


def stop_attack_monitor():
    global _attack_monitor
    if _attack_monitor:
        _attack_monitor.stop()
        _attack_monitor = None
        log("INFO", "Attack monitor stopped.")


def notify_blacklist(ip: str):
    """Call this whenever an IP is blacklisted to fire the Discord alert."""
    if _notifier:
        _notifier.alert_blacklist(ip)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def run(cmd: str, check=True, capture=False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True
    )

def require_root():
    if os.geteuid() != 0:
        print(f"{R}[ERROR]{NC} Must be run as root (sudo).")
        sys.exit(1)

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_default_interface() -> str:
    result = run("ip route | grep default | awk '{print $5}' | head -1",
                 capture=True, check=False)
    iface = result.stdout.strip()
    return iface if iface else "eth0"

def load_whitelist() -> list[str]:
    if not WHITELIST_FILE.exists():
        return []
    return [
        line.strip() for line in WHITELIST_FILE.read_text().splitlines()
        if line.strip() and not line.startswith("#") and validate_ip(line.strip())
    ]

def load_blacklist() -> list[str]:
    if not BLACKLIST_FILE.exists():
        return []
    return [
        line.strip() for line in BLACKLIST_FILE.read_text().splitlines()
        if line.strip() and not line.startswith("#") and validate_ip(line.strip())
    ]

def save_state(state: dict):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"running": False, "interface": "", "xdp_mode": ""}

# ─── Dependency Checks ────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "iptables":  "iptables",
    "ipset":     "ipset",
    "ip":        "iproute2",
    "bpftool":   "linux-tools-common linux-tools-$(uname -r)",
    "clang":     "clang",
    "llc":       "llvm",
}

def check_dependencies() -> bool:
    missing = []
    for tool, pkg in REQUIRED_TOOLS.items():
        if not shutil.which(tool):
            missing.append((tool, pkg))
    if missing:
        log("ERROR", "Missing dependencies:")
        for tool, pkg in missing:
            print(f"    {R}✗{NC}  {tool}  →  sudo apt install {pkg}")
        return False
    log("INFO", "All dependencies satisfied.")
    return True

# ─── Layer 1: XDP/eBPF ───────────────────────────────────────────────────────

def compile_xdp() -> bool:
    """Compile xdp_filter.c → xdp_filter.o"""
    src = XDP_SRC
    if not src.exists():
        log("WARN", "xdp_filter.c not found — XDP layer disabled.")
        return False

    BASE_DIR.mkdir(parents=True, exist_ok=True)

    # Detect kernel include path
    uname = run("uname -r", capture=True, check=False).stdout.strip()
    kernel_inc = f"/usr/src/linux-headers-{uname}/include"
    if not Path(kernel_inc).exists():
        kernel_inc = "/usr/include"

    cmd = (
        f"clang -O2 -target bpf "
        f"-I{kernel_inc} "
        f"-I/usr/include/x86_64-linux-gnu "
        f"-c {src} -o {XDP_OBJ}"
    )
    log("INFO", f"Compiling XDP program: {cmd}")
    result = run(cmd, check=False, capture=True)
    if result.returncode != 0:
        log("WARN", f"XDP compile failed: {result.stderr.strip()}")
        log("WARN", "Continuing without XDP layer.")
        return False
    log("INFO", f"XDP object compiled → {XDP_OBJ}")
    return True

def attach_xdp(iface: str) -> str:
    """Try native XDP, fall back to xdpgeneric. Returns mode string."""
    if not XDP_OBJ.exists():
        return ""

    # Detach any existing XDP program first
    run(f"ip link set dev {iface} xdp off", check=False)

    # Try native (fastest)
    r = run(f"ip link set dev {iface} xdp obj {XDP_OBJ} sec xdp",
            check=False, capture=True)
    if r.returncode == 0:
        log("INFO", f"XDP attached in {G}NATIVE{NC} mode on {iface}")
        return "native"

    # Fall back to generic
    r = run(f"ip link set dev {iface} xdpgeneric obj {XDP_OBJ} sec xdp",
            check=False, capture=True)
    if r.returncode == 0:
        log("INFO", f"XDP attached in {Y}GENERIC{NC} mode on {iface}")
        return "generic"

    log("WARN", f"XDP attach failed: {r.stderr.strip()}")
    return ""

def detach_xdp(iface: str):
    run(f"ip link set dev {iface} xdp off", check=False)
    run(f"ip link set dev {iface} xdpgeneric off", check=False)
    log("INFO", f"XDP detached from {iface}")

def xdp_populate_whitelist(ips: list[str]):
    """Push whitelist IPs into the BPF map via bpftool."""
    if not shutil.which("bpftool"):
        return
    for ip in ips:
        try:
            packed = int(ipaddress.IPv4Address(ip))
            # bpftool expects hex key in little-endian for network byte order
            hex_key = format(socket.htonl(packed), "08x")
            run(f"bpftool map update name ip_whitelist key hex {' '.join(hex_key[i:i+2] for i in range(0,8,2))} value hex 01 any",
                check=False, capture=True)
        except Exception:
            pass

def xdp_populate_blacklist(ips: list[str]):
    if not shutil.which("bpftool"):
        return
    for ip in ips:
        try:
            packed = int(ipaddress.IPv4Address(ip))
            hex_key = format(socket.htonl(packed), "08x")
            run(f"bpftool map update name ip_blacklist key hex {' '.join(hex_key[i:i+2] for i in range(0,8,2))} value hex 01 any",
                check=False, capture=True)
        except Exception:
            pass

# ─── Layer 2: iptables mangle ─────────────────────────────────────────────────

def setup_mangle(whitelist: list[str]):
    log("INFO", "Setting up Layer 2 — iptables mangle (pre-routing scrub)…")

    cmds = [
        # Flush existing mangle PREROUTING rules we own
        "iptables -t mangle -F PREROUTING 2>/dev/null || true",

        # ── Whitelist bypass ─────────────────────────────────────────────────
        *[f"iptables -t mangle -A PREROUTING -s {ip} -j ACCEPT" for ip in whitelist],

        # ── Bogus TCP flags ──────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN     -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG     -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE        -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL         -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP",

        # ── Bogus SYN packets ────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp ! --syn -m state --state NEW -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp -m state --state INVALID     -j DROP",

        # ── MSS spoofing / tiny SYN ──────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp --syn -m length --length 0:40 -j DROP",

        # ── IP fragment attacks ──────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -f -j DROP",

        # ── Private / spoofed source IPs on public interfaces ───────────────
        # (soft: LOG before DROP to avoid breaking LAN setups)
        "iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP",
        "iptables -t mangle -A PREROUTING -s 192.0.2.0/24   -j DROP",
        "iptables -t mangle -A PREROUTING -s 198.51.100.0/24 -j DROP",
        "iptables -t mangle -A PREROUTING -s 203.0.113.0/24  -j DROP",
        "iptables -t mangle -A PREROUTING -s 240.0.0.0/5     -j DROP",
        "iptables -t mangle -A PREROUTING -s 0.0.0.0/8       -j DROP",

        # ── Limit ICMP ───────────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p icmp -m hashlimit "
            "--hashlimit-upto 5/s --hashlimit-burst 10 "
            "--hashlimit-mode srcip --hashlimit-name icmp_pre -j ACCEPT",
        "iptables -t mangle -A PREROUTING -p icmp -j DROP",
    ]

    for cmd in cmds:
        run(cmd, check=False)

    log("INFO", f"  {G}✓{NC} Mangle/PREROUTING rules applied.")

def teardown_mangle():
    run("iptables -t mangle -F PREROUTING 2>/dev/null || true", check=False)
    log("INFO", "Layer 2 mangle rules removed.")

# ─── Layer 3: ipset blacklist ─────────────────────────────────────────────────

IPSET_BL = "antiddos_blacklist"
IPSET_WL = "antiddos_whitelist"

def setup_ipset(whitelist: list[str], blacklist: list[str]):
    log("INFO", "Setting up Layer 3 — ipset hash:ip lists…")

    # Destroy & recreate
    run(f"ipset destroy {IPSET_BL} 2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_WL} 2>/dev/null || true", check=False)
    run(f"ipset create {IPSET_BL} hash:ip maxelem 1000000 hashsize 65536 timeout 0", check=False)
    run(f"ipset create {IPSET_WL} hash:ip maxelem 65536  hashsize 4096   timeout 0", check=False)

    # Populate whitelist set
    for ip in whitelist:
        run(f"ipset add {IPSET_WL} {ip} 2>/dev/null || true", check=False)

    # Populate blacklist set
    for ip in blacklist:
        run(f"ipset add {IPSET_BL} {ip} 2>/dev/null || true", check=False)

    # iptables rules referencing the sets
    run(f"iptables -I INPUT 1 -m set --match-set {IPSET_WL} src -j ACCEPT")
    run(f"iptables -I INPUT 2 -m set --match-set {IPSET_BL} src -j DROP")

    log("INFO", f"  {G}✓{NC} ipset lists created  "
                f"(whitelist={len(whitelist)}, blacklist={len(blacklist)} IPs).")

def teardown_ipset():
    run(f"iptables -D INPUT -m set --match-set {IPSET_WL} src -j ACCEPT 2>/dev/null || true", check=False)
    run(f"iptables -D INPUT -m set --match-set {IPSET_BL} src -j DROP   2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_BL} 2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_WL} 2>/dev/null || true", check=False)
    log("INFO", "Layer 3 ipset lists removed.")

# ─── Layer 4: Application Chains ─────────────────────────────────────────────

def setup_application_chains(whitelist: list[str]):
    log("INFO", "Setting up Layer 4 — application flood-guard chains…")

    def ipt(cmd):
        run(f"iptables {cmd}", check=False)

    # Flush & recreate custom chains
    for chain in ["TCP_FLOOD", "UDP_FLOOD", "ICMP_GUARD"]:
        ipt(f"-N {chain} 2>/dev/null || true")
        ipt(f"-F {chain}")

    # ── Whitelist bypass in INPUT ────────────────────────────────────────────
    for ip in whitelist:
        ipt(f"-I INPUT -s {ip} -j ACCEPT")

    # ── Allow established/related ────────────────────────────────────────────
    ipt("-I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT")
    ipt("-I INPUT 2 -i lo -j ACCEPT")

    # ── SSH — open to all, no whitelist restriction ──────────────────────────
    ipt("-A INPUT -p tcp --dport 22 -j ACCEPT")

    # ── HTTP / HTTPS / phpMyAdmin (port 20080) — open, no rate limit ─────────
    for port in ["80", "443", "20080"]:
        ipt(f"-A INPUT -p tcp --dport {port} -j ACCEPT")

    # ── MTA Masterlist / Browser UDP (BEFORE flood chains) ───────────────────
    for port in ["22126", "22129", "22132", "22135", "22138", "22141", "22144", "22153"]:
        ipt(f"-A INPUT -p udp --dport {port} -j ACCEPT")

    # ── MTA UDP — no limit (required for download) ────────────────────────────
    for port in ["22003", "22006", "22009", "22012", "22015", "22018", "22021", "22030"]:
        ipt(f"-A INPUT -p udp --dport {port} -j ACCEPT")

    # ── MTA TCP ───────────────────────────────────────────────────────────────
    for port in ["22006", "22009", "22012", "22015", "22018", "22021", "22024", "22033"]:
        ipt(f"-A INPUT -p tcp --dport {port} -j ACCEPT")

    # ── Dispatch to sub-chains ───────────────────────────────────────────────
    ipt("-A INPUT -p tcp  -j TCP_FLOOD")
    ipt("-A INPUT -p udp  -j UDP_FLOOD")
    ipt("-A INPUT -p icmp -j ICMP_GUARD")

    # ── TCP_FLOOD chain ──────────────────────────────────────────────────────
    # Raised from 25→100/s: players connect TCP on join + HTTP resource download.
    # 8 servers × ~12 joins/min peak = ~1.6/s normally; 100/s gives headroom.
    ipt("-A TCP_FLOOD -p tcp --syn "
        "-m hashlimit --hashlimit-upto 100/s --hashlimit-burst 200 "
        "--hashlimit-mode srcip --hashlimit-name syn_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --syn -j DROP")

    # ACK flood — raised to 1000/s, burst 2000 (game TCP keepalives are chatty)
    ipt("-A TCP_FLOOD -p tcp --tcp-flags ACK ACK "
        "-m hashlimit --hashlimit-upto 1000/s --hashlimit-burst 2000 "
        "--hashlimit-mode srcip --hashlimit-name ack_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --tcp-flags ACK ACK -j DROP")

    # RST flood — raised to 10/s: disconnects from 8 servers can burst RSTs
    ipt("-A TCP_FLOOD -p tcp --tcp-flags RST RST "
        "-m hashlimit --hashlimit-upto 10/s --hashlimit-burst 20 "
        "--hashlimit-mode srcip --hashlimit-name rst_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --tcp-flags RST RST -j DROP")

    ipt("-A TCP_FLOOD -j ACCEPT")

    # ── UDP_FLOOD chain ──────────────────────────────────────────────────────
    # Hard-block UDP amplification SOURCE ports (attacker-reflected traffic)
    AMPLIFICATION_PORTS = [
        19,    # Chargen      — amplification factor ~358x
        111,   # portmap      — amplification factor ~7x
        123,   # NTP          — amplification factor ~556x  ← most common
        137,   # NetBIOS      — amplification factor ~3x
        161,   # SNMP         — amplification factor ~650x  ← most dangerous
        389,   # LDAP         — amplification factor ~46x
        1900,  # SSDP/UPnP    — amplification factor ~30x
        3702,  # WSD          — amplification factor ~80x
        11211, # Memcached    — amplification factor ~50,000x ← catastrophic
        27015, # Steam/Source — amplification factor ~5x
    ]
    for port in AMPLIFICATION_PORTS:
        ipt(f"-A UDP_FLOOD -p udp --sport {port} -j DROP")

    # DNS: this server is NOT a DNS server — cap tightly
    ipt("-A UDP_FLOOD -p udp --dport 53 "
        "-m hashlimit --hashlimit-upto 5/s --hashlimit-burst 10 "
        "--hashlimit-mode srcip --hashlimit-name udp_dns "
        "-j ACCEPT")
    ipt("-A UDP_FLOOD -p udp --dport 53 -j DROP")

    # General UDP — raised from 50→500/s per IP, burst 1000.
    # MTA game traffic is pure UDP: position updates ~20 pps per player,
    # so one player with 8 servers could legitimately send 160 pps.
    # 500/s gives 3× headroom before cutting off a real player.
    ipt("-A UDP_FLOOD -p udp "
        "-m hashlimit --hashlimit-upto 500/s --hashlimit-burst 1000 "
        "--hashlimit-mode srcip --hashlimit-name udp_generic "
        "-j ACCEPT")
    ipt("-A UDP_FLOOD -p udp -j DROP")

    # ── ICMP_GUARD chain ─────────────────────────────────────────────────────
    # Raised echo-request to 2/s: players ping the server list on browser refresh.
    # 8 servers × players refreshing = legitimate ICMP bursts.
    ipt("-A ICMP_GUARD -p icmp --icmp-type echo-request "
        "-m hashlimit --hashlimit-upto 2/s --hashlimit-burst 10 "
        "--hashlimit-mode srcip --hashlimit-name icmp_guard "
        "-j ACCEPT")
    ipt("-A ICMP_GUARD -p icmp --icmp-type echo-reply   -j ACCEPT")
    ipt("-A ICMP_GUARD -p icmp --icmp-type 3            -j ACCEPT")  # unreachable
    ipt("-A ICMP_GUARD -p icmp --icmp-type 11           -j ACCEPT")  # TTL exceeded
    ipt("-A ICMP_GUARD -p icmp -j DROP")

    log("INFO", f"  {G}✓{NC} TCP_FLOOD / UDP_FLOOD / ICMP_GUARD chains active.")

def teardown_application_chains():
    def ipt(cmd):
        run(f"iptables {cmd}", check=False)

    for chain in ["TCP_FLOOD", "UDP_FLOOD", "ICMP_GUARD"]:
        ipt(f"-D INPUT -p tcp  -j {chain} 2>/dev/null || true")
        ipt(f"-D INPUT -p udp  -j {chain} 2>/dev/null || true")
        ipt(f"-D INPUT -p icmp -j {chain} 2>/dev/null || true")
        ipt(f"-F {chain} 2>/dev/null || true")
        ipt(f"-X {chain} 2>/dev/null || true")

    log("INFO", "Layer 4 application chains removed.")

# ─── Kernel Hardening (sysctl) ────────────────────────────────────────────────

SYSCTL_SETTINGS = {
    "net.ipv4.tcp_syncookies":           "1",
    "net.ipv4.tcp_syn_retries":          "2",
    "net.ipv4.tcp_synack_retries":       "2",
    "net.ipv4.tcp_max_syn_backlog":      "4096",
    "net.ipv4.conf.all.rp_filter":       "1",   # reverse-path filtering
    "net.ipv4.conf.default.rp_filter":   "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects":   "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians":    "1",
    "net.ipv4.tcp_rfc1337":             "1",
    "net.ipv4.tcp_fin_timeout":         "15",
    "net.ipv4.tcp_keepalive_time":      "300",
    "net.ipv4.tcp_keepalive_probes":    "5",
    "net.ipv4.tcp_keepalive_intvl":     "15",
}

def apply_sysctl():
    log("INFO", "Applying kernel hardening (sysctl)…")
    for key, val in SYSCTL_SETTINGS.items():
        run(f"sysctl -w {key}={val}", check=False, capture=True)
    log("INFO", f"  {G}✓{NC} sysctl hardening applied.")

def restore_sysctl():
    """Restore only the settings we explicitly changed back to safe defaults."""
    restore_map = {
        "net.ipv4.tcp_syncookies":                    "1",
        "net.ipv4.tcp_syn_retries":                   "6",
        "net.ipv4.tcp_synack_retries":                "5",
        "net.ipv4.tcp_max_syn_backlog":               "128",
        "net.ipv4.conf.all.rp_filter":                "1",
        "net.ipv4.conf.default.rp_filter":            "1",
        "net.ipv4.icmp_echo_ignore_broadcasts":       "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.conf.all.accept_redirects":         "1",
        "net.ipv4.conf.all.send_redirects":           "1",
        "net.ipv4.conf.all.accept_source_route":      "0",
        "net.ipv4.conf.all.log_martians":             "0",
        "net.ipv4.tcp_rfc1337":                       "0",
        "net.ipv4.tcp_fin_timeout":                   "60",
        "net.ipv4.tcp_keepalive_time":                "7200",
        "net.ipv4.tcp_keepalive_probes":              "9",
        "net.ipv4.tcp_keepalive_intvl":               "75",
    }
    for key, val in restore_map.items():
        run(f"sysctl -w {key}={val}", check=False, capture=True)

# ─── Main CLI Commands ────────────────────────────────────────────────────────

def cmd_start(args):
    require_root()
    banner()

    state = load_state()
    if state.get("running"):
        log("WARN", "Anti-DDoS is already running. Use --stop first.")
        sys.exit(1)

    BASE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialise config files if absent
    if not WHITELIST_FILE.exists():
        WHITELIST_FILE.write_text("# Anti-DDoS Whitelist — one IP per line\n")
    if not BLACKLIST_FILE.exists():
        BLACKLIST_FILE.write_text("# Anti-DDoS Blacklist — one IP per line\n")

    iface = getattr(args, "interface", None) or get_default_interface()
    log("INFO", f"Using network interface: {C}{iface}{NC}")

    whitelist = load_whitelist()
    blacklist = load_blacklist()

    log("INFO", f"Whitelist: {len(whitelist)} IPs  |  Blacklist: {len(blacklist)} IPs")

    # ── Layer 1: XDP ──────────────────────────────────────────────────────────
    xdp_mode = ""
    if not args.no_xdp:
        compiled = compile_xdp()
        if compiled:
            xdp_mode = attach_xdp(iface)
            if xdp_mode:
                xdp_populate_whitelist(whitelist)
                xdp_populate_blacklist(blacklist)

    # ── Layer 2: mangle ───────────────────────────────────────────────────────
    apply_sysctl()
    setup_mangle(whitelist)

    # ── Layer 3: ipset ────────────────────────────────────────────────────────
    setup_ipset(whitelist, blacklist)

    # ── Layer 4: application chains ───────────────────────────────────────────
    setup_application_chains(whitelist)

    save_state({"running": True, "interface": iface, "xdp_mode": xdp_mode,
                "started": time.strftime("%Y-%m-%d %H:%M:%S")})

    # Start background attack monitor (Discord alerts)
    start_attack_monitor()

    print(f"\n  {G}{BOLD}Anti-DDoS protection ACTIVE{NC}")
    print(f"  {'Layer':<10} {'Status':<12} {'Details'}")
    print(f"  {'─'*50}")
    xdp_label = f"{G}✓ {xdp_mode.upper()}{NC}" if xdp_mode else f"{Y}⚠ SKIPPED{NC}"
    print(f"  {'XDP':<10} {xdp_label:<30} driver-level packet filter")
    print(f"  {'Mangle':<10} {G}✓ ACTIVE{NC:<30} bogus-flag scrubber")
    print(f"  {'ipset':<10} {G}✓ ACTIVE{NC:<30} O(1) IP blacklist ({len(blacklist)} IPs)")
    print(f"  {'Chains':<10} {G}✓ ACTIVE{NC:<30} flood/brute-force guards")
    print()

def cmd_stop(args):
    require_root()
    state = load_state()
    iface = state.get("interface") or get_default_interface()

    log("INFO", "Stopping Anti-DDoS protection…")

    stop_attack_monitor()

    detach_xdp(iface)
    teardown_mangle()
    teardown_ipset()
    teardown_application_chains()
    restore_sysctl()

    save_state({"running": False, "interface": "", "xdp_mode": ""})
    log("INFO", f"{G}All layers deactivated. Server is unprotected.{NC}")

def cmd_status(args):
    state = load_state()
    running = state.get("running", False)
    banner()

    status_str = f"{G}ACTIVE{NC}" if running else f"{R}INACTIVE{NC}"
    print(f"  Status   : {BOLD}{status_str}{NC}")
    if running:
        print(f"  Interface: {C}{state.get('interface')}{NC}")
        print(f"  XDP Mode : {state.get('xdp_mode') or 'disabled'}")
        print(f"  Started  : {state.get('started', 'unknown')}")
        print()

    whitelist = load_whitelist()
    blacklist  = load_blacklist()
    print(f"  Whitelist IPs : {len(whitelist)}")
    print(f"  Blacklist IPs : {len(blacklist)}")

    if whitelist:
        print(f"\n  {C}Whitelisted:{NC}")
        for ip in whitelist[:10]:
            print(f"    {G}✓{NC}  {ip}")
        if len(whitelist) > 10:
            print(f"    … and {len(whitelist)-10} more")

    if blacklist:
        print(f"\n  {R}Blacklisted:{NC}")
        for ip in blacklist[:10]:
            print(f"    {R}✗{NC}  {ip}")
        if len(blacklist) > 10:
            print(f"    … and {len(blacklist)-10} more")

    # iptables chain stats
    print(f"\n  {B}iptables DROP counters:{NC}")
    r = run("iptables -L INPUT -v -n --line-numbers 2>/dev/null",
            capture=True, check=False)
    if r.stdout:
        lines = r.stdout.strip().splitlines()
        for line in lines:
            if "DROP" in line or "Chain" in line or "pkts" in line:
                print(f"    {DIM}{line}{NC}")
    print()

def whitelist_add_ip(ip: str, silent=False):
    if not validate_ip(ip):
        if not silent:
            log("ERROR", f"Invalid IP address: {ip}")
        return False
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    WHITELIST_FILE.touch(exist_ok=True)
    existing = WHITELIST_FILE.read_text()
    if ip in existing.splitlines():
        if not silent:
            log("INFO", f"{ip} already in whitelist.")
        return True
    with open(WHITELIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    if not silent:
        log("INFO", f"Added {G}{ip}{NC} to whitelist.")

    # Live update if running
    state = load_state()
    if state.get("running"):
        run(f"ipset add {IPSET_WL} {ip} 2>/dev/null || true", check=False)
        # Also remove from blacklist if present
        run(f"ipset del {IPSET_BL} {ip} 2>/dev/null || true", check=False)
        if not silent:
            log("INFO", "Live-updated running ipset.")
    return True

def cmd_whitelist_add(args):
    require_root()
    whitelist_add_ip(args.ip)

def cmd_blacklist_add(args):
    require_root()
    ip = args.ip
    if not validate_ip(ip):
        log("ERROR", f"Invalid IP address: {ip}")
        sys.exit(1)
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    BLACKLIST_FILE.touch(exist_ok=True)
    existing = BLACKLIST_FILE.read_text()
    if ip in existing.splitlines():
        log("INFO", f"{ip} already in blacklist.")
        return
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    log("INFO", f"Added {R}{ip}{NC} to blacklist.")
    notify_blacklist(ip)

    state = load_state()
    if state.get("running"):
        run(f"ipset add {IPSET_BL} {ip} 2>/dev/null || true", check=False)
        log("INFO", "Live-updated running ipset.")

def cmd_blacklist_remove(args):
    require_root()
    ip = args.ip
    if not validate_ip(ip):
        log("ERROR", f"Invalid IP address: {ip}")
        sys.exit(1)
    if BLACKLIST_FILE.exists():
        lines = [l for l in BLACKLIST_FILE.read_text().splitlines() if l.strip() != ip]
        BLACKLIST_FILE.write_text("\n".join(lines) + "\n")
    run(f"ipset del {IPSET_BL} {ip} 2>/dev/null || true", check=False)
    log("INFO", f"Removed {ip} from blacklist.")

# ─── Live Monitor ─────────────────────────────────────────────────────────────

class Monitor:
    """Real-time stats display: PPS, bandwidth, drop counters."""

    CLEAR = "\033[2J\033[H"

    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self._iface   = load_state().get("interface") or get_default_interface()
        signal.signal(signal.SIGINT, self._handle_exit)

    def _handle_exit(self, *_):
        print(f"\n\n  {Y}Monitor stopped.{NC}\n")
        sys.exit(0)

    def _read_net_stats(self) -> tuple[int, int, int, int]:
        """Returns (rx_bytes, rx_packets, tx_bytes, tx_packets)."""
        path = Path(f"/sys/class/net/{self._iface}/statistics")
        try:
            rx_b = int((path / "rx_bytes").read_text())
            rx_p = int((path / "rx_packets").read_text())
            tx_b = int((path / "tx_bytes").read_text())
            tx_p = int((path / "tx_packets").read_text())
            return rx_b, rx_p, tx_b, tx_p
        except Exception:
            return 0, 0, 0, 0

    def _get_xdp_stats(self) -> dict[str, int]:
        """Read per-CPU counters from BPF map via bpftool."""
        stats = {"bl_drops": 0, "flag_drops": 0, "frag_drops": 0, "total": 0}
        if not shutil.which("bpftool"):
            return stats
        r = run("bpftool map dump name xdp_stats 2>/dev/null", capture=True, check=False)
        # Parse JSON output
        try:
            data = json.loads(r.stdout)
            for entry in data:
                key = entry.get("key", [0])[0]
                val = sum(entry.get("values", [0]))
                if key == 0:   stats["bl_drops"]   = val
                elif key == 1: stats["flag_drops"]  = val
                elif key == 2: stats["frag_drops"]  = val
                elif key == 3: stats["total"]       = val
        except Exception:
            pass
        return stats

    def _get_blocked_ips(self, n=10) -> list[str]:
        r = run(f"ipset list {IPSET_BL} 2>/dev/null | tail -{n}",
                capture=True, check=False)
        return [l.strip() for l in r.stdout.splitlines() if validate_ip(l.strip())]

    def _fmt_bytes(self, b: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}/s"
            b /= 1024
        return f"{b:.1f} TB/s"

    def run(self):
        print(f"\n  {C}Live monitor starting — press {BOLD}Ctrl+C{NC}{C} to quit{NC}\n")
        rx_b0, rx_p0, tx_b0, tx_p0 = self._read_net_stats()
        t0 = time.time()

        while True:
            time.sleep(self.interval)
            rx_b1, rx_p1, tx_b1, tx_p1 = self._read_net_stats()
            t1 = time.time()
            dt = t1 - t0 or 1

            rx_bps = max(0, rx_b1 - rx_b0) / dt
            tx_bps = max(0, tx_b1 - tx_b0) / dt
            rx_pps = max(0, rx_p1 - rx_p0) / dt
            tx_pps = max(0, tx_p1 - tx_p0) / dt

            rx_b0, rx_p0, tx_b0, tx_p0 = rx_b1, rx_p1, tx_b1, tx_p1
            t0 = t1

            xdp   = self._get_xdp_stats()
            bl_ips = self._get_blocked_ips(8)

            ts = time.strftime("%H:%M:%S")
            print(self.CLEAR, end="")
            print(f"""
{B}{BOLD} ╔══════════════════════════════════════════════════════════╗
 ║   Anti-DDoS Live Monitor  ·  {ts}  ·  iface: {self._iface:<6}    ║
 ╚══════════════════════════════════════════════════════════╝{NC}

 {BOLD}Traffic{NC}
  ↓ Inbound  : {G}{self._fmt_bytes(rx_bps):<18}{NC}  {rx_pps:>8.0f} pps
  ↑ Outbound : {C}{self._fmt_bytes(tx_bps):<18}{NC}  {tx_pps:>8.0f} pps

 {BOLD}XDP Drop Counters{NC}
  Blacklist  drops : {R}{xdp['bl_drops']:>12,}{NC}
  Bad-flags  drops : {R}{xdp['flag_drops']:>12,}{NC}
  Fragment   drops : {R}{xdp['frag_drops']:>12,}{NC}
  Total      seen  : {DIM}{xdp['total']:>12,}{NC}

 {BOLD}Currently Blocked IPs (last {len(bl_ips)}){NC}""")

            if bl_ips:
                for ip in bl_ips:
                    print(f"  {R}✗{NC}  {ip}")
            else:
                print(f"  {DIM}(none){NC}")

            state = load_state()
            prot = f"{G}ACTIVE{NC}" if state.get("running") else f"{R}INACTIVE{NC}"
            print(f"\n  Protection: {BOLD}{prot}{NC}  |  "
                  f"XDP: {state.get('xdp_mode') or 'off'}  |  "
                  f"[Ctrl+C to quit]")

def cmd_monitor(args):
    Monitor(interval=float(getattr(args, "interval", 1.0))).run()

# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="antiddos",
        description="4-Layer Anti-DDoS Protection for Ubuntu VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 antiddos.py --start
  sudo python3 antiddos.py --start --interface eth0
  sudo python3 antiddos.py --stop
  sudo python3 antiddos.py --status
  sudo python3 antiddos.py --monitor
  sudo python3 antiddos.py --whitelist-add 1.2.3.4
  sudo python3 antiddos.py --blacklist-add 5.6.7.8
  sudo python3 antiddos.py --blacklist-remove 5.6.7.8
  sudo python3 antiddos.py --check-deps
"""
    )

    p.add_argument("--start",            action="store_true", help="Activate all 4 protection layers")
    p.add_argument("--stop",             action="store_true", help="Deactivate all layers")
    p.add_argument("--status",           action="store_true", help="Show current protection status")
    p.add_argument("--monitor",          action="store_true", help="Live traffic & drop stats")
    p.add_argument("--whitelist-add",    metavar="IP",        help="Add IP to whitelist (bypasses all layers)")
    p.add_argument("--blacklist-add",    metavar="IP",        help="Add IP to blacklist")
    p.add_argument("--blacklist-remove", metavar="IP",        help="Remove IP from blacklist")
    p.add_argument("--check-deps",       action="store_true", help="Check required dependencies")
    p.add_argument("--interface",        metavar="IFACE",     help="Network interface (default: auto-detect)")
    p.add_argument("--no-xdp",          action="store_true", help="Skip Layer 1 XDP (iptables only)")
    p.add_argument("--interval",         metavar="SEC",       type=float, default=1.0,
                   help="Monitor refresh interval in seconds (default: 1)")
    return p

# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.start:
        cmd_start(args)
    elif args.stop:
        cmd_stop(args)
    elif args.status:
        cmd_status(args)
    elif args.monitor:
        cmd_monitor(args)
    elif args.whitelist_add:
        require_root()
        args.ip = args.whitelist_add
        cmd_whitelist_add(args)
    elif args.blacklist_add:
        require_root()
        args.ip = args.blacklist_add
        cmd_blacklist_add(args)
    elif args.blacklist_remove:
        require_root()
        args.ip = args.blacklist_remove
        cmd_blacklist_remove(args)
    elif args.check_deps:
        check_dependencies()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
