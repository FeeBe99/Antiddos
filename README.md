# Anti-DDoS 4-Layer Defense Architecture
**Ubuntu VPS — Python + XDP/eBPF + iptables**

---

## Architecture Overview

```
INTERNET
   │
   ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 1 — XDP/eBPF  (~100 ns)                       │
│  • Blacklisted IPs  → XDP_DROP (hash:ip map)        │
│  • Whitelisted IPs  → XDP_PASS (bypass all layers)  │
│  • Bogus TCP flags  → XDP_DROP (NULL/XMAS/SYN+FIN)  │
│  • IP fragments     → XDP_DROP (tiny fragments)     │
└──────────────────────────┬──────────────────────────┘
                           │ XDP_PASS
                           ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 2 — iptables mangle PREROUTING  (~5 µs)       │
│  • Scrub bogus TCP flag combos (10 patterns)        │
│  • Drop non-SYN new connections                     │
│  • Drop IP fragments (f flag)                       │
│  • Drop spoofed/reserved source IPs                 │
│  • ICMP rate-limit (5 pps burst-10)                 │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 3 — ipset hash:ip  (O(1))                     │
│  • antiddos_whitelist  → ACCEPT  (max 65,536)       │
│  • antiddos_blacklist  → DROP    (max 1,000,000)    │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 4 — iptables Application Chains               │
│  TCP_FLOOD  : SYN 25/s, ACK 500/s, RST 2/s hashlimit│
│  UDP_FLOOD  : block amplification ports, 50 pps cap │
│  ICMP_GUARD : echo-req 1/s, allow types 0/3/11      │
│  SSH_GUARD  : 3 new conn/min per IP (brute-force)   │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
                     YOUR APPLICATION
```

---

## Files

| File | Purpose |
|------|---------|
| `antiddos.py` | Main Python orchestrator & CLI |
| `xdp_filter.c` | XDP/eBPF C program (Layer 1) |
| `install.sh` | Dependency installer & setup |
| `/etc/antiddos/whitelist.conf` | Trusted IPs (bypass all layers) |
| `/etc/antiddos/blacklist.conf` | Blocked IPs |
| `/etc/antiddos/xdp_filter.o` | Compiled BPF object |
| `/etc/antiddos/state.json` | Runtime state |
| `/etc/antiddos/antiddos.log` | Log file |

---

## Installation

```bash
# 1. Install all dependencies (run once)
sudo bash install.sh

# 2. Verify dependencies
sudo antiddos --check-deps

# 3. Start protection
sudo antiddos --start
```

---

## CLI Reference

```bash
# Core commands
sudo antiddos --start                   # Activate all 4 layers
sudo antiddos --stop                    # Deactivate all layers
sudo antiddos --status                  # Show status + counters
sudo antiddos --monitor                 # Live traffic dashboard
sudo antiddos --monitor --interval 0.5  # Faster refresh (0.5s)

# IP management
sudo antiddos --whitelist-add  1.2.3.4  # Bypass all layers
sudo antiddos --blacklist-add  5.6.7.8  # Block immediately (live)
sudo antiddos --blacklist-remove 5.6.7.8

# Advanced
sudo antiddos --start --interface eth1  # Specify NIC
sudo antiddos --start --no-xdp          # Skip XDP (iptables only)
sudo antiddos --check-deps              # Dependency check
```

---

## Dependencies

```bash
# All installed automatically by install.sh
sudo apt install \
    iptables \
    ipset \
    iproute2 \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    libbpf-dev
```

---

## XDP Compilation (manual)

```bash
KERNEL=$(uname -r)
clang -O2 -target bpf \
    -I/usr/src/linux-headers-${KERNEL}/include \
    -I/usr/include/x86_64-linux-gnu \
    -c xdp_filter.c -o /etc/antiddos/xdp_filter.o
```

If your NIC doesn't support native XDP, the script automatically falls back to `xdpgeneric` mode (works on all drivers, slightly higher latency).

---

## Auto-start on Boot

```bash
sudo systemctl enable antiddos
sudo systemctl start  antiddos
sudo systemctl status antiddos
```

---

## Safety Notes

- **SSH auto-whitelist**: On `--start`, your current SSH session IP is automatically added to the whitelist so you cannot lock yourself out.
- **Whitelist takes absolute priority**: Whitelisted IPs skip XDP maps, mangle rules, ipset, and all application chains.
- **Live updates**: `--blacklist-add` and `--whitelist-add` take effect immediately without a restart if protection is already running.

---

## Rate Limits (Layer 4 defaults)

| Traffic Type | Limit | Burst |
|-------------|-------|-------|
| SYN packets | 25/s per IP | 50 |
| ACK packets | 500/s per IP | 1000 |
| RST packets | 2/s per IP | 5 |
| UDP generic | 50/s per IP | 100 |
| ICMP echo | 1/s per IP | 5 |
| SSH new conn | 3/min per IP | — |

Edit `antiddos.py` → `setup_application_chains()` to adjust these values.

---

## Tuning the ipset for 1 Million IPs

The blacklist ipset is pre-configured with:
```
maxelem 1000000   # 1 million entries
hashsize 65536    # initial hash buckets (auto-grows)
timeout 0         # no expiry (permanent entries)
```
Memory usage: ~50–80 MB for 1M entries. All lookups are O(1).
