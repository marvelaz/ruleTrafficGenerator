"""
Phase 2 — Traffic Generation
Generates low-volume, log-observable traffic between LinuxA and LinuxB
in both directions using Scapy.

Protocols: TCP (varied ports), ICMP, HTTP (layer 7), DNS
Target: match 60-75% of configured rules (configurable via match_ratio)

Requirements: root / CAP_NET_RAW on both hosts.
Run on LinuxA for inside→outside traffic.
Run on LinuxB for outside→inside traffic.

Usage:
  sudo python3 phase2_traffic.py --config config.yaml --direction in2out
  sudo python3 phase2_traffic.py --config config.yaml --direction out2in
  sudo python3 phase2_traffic.py --config config.yaml --direction both
"""

import ipaddress
import json
import logging
import random
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.live import Live
from rich.table import Table

log = logging.getLogger(__name__)
console = Console()

# Global stop flag — set by SIGINT/SIGTERM
_STOP = False


def _signal_handler(sig, frame):
    global _STOP
    console.print("\n[yellow]Stop signal received — finishing current session...")
    _STOP = True


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# IP alias management
# ---------------------------------------------------------------------------

def setup_ip_aliases(interface: str, aliases: list[str], remove: bool = False):
    """
    Add or remove IP aliases on a Linux interface using `ip addr`.
    Requires root. Called once at startup on each host.
    """
    import subprocess
    action = "del" if remove else "add"
    for ip in aliases:
        cmd = ["ip", "addr", action, f"{ip}/24", "dev", interface]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            log.info(f"{'Removed' if remove else 'Added'} alias {ip} on {interface}")
        except subprocess.CalledProcessError as e:
            # Ignore "already exists" on add, "not found" on del
            log.debug(f"alias {action} {ip}: {e.stderr.decode().strip()}")


# ---------------------------------------------------------------------------
# Target selector — determines which rules to match vs skip
# ---------------------------------------------------------------------------

class TrafficTargetSelector:
    """
    Loads the generated rules from phase1 and selects which rule-src/dst/svc
    combos to generate traffic for, targeting match_ratio of total rules.

    Uses round-robin cycling through the target set (shuffled each full pass)
    so every target rule gets at least one hit before any rule gets a second hit.
    Pure-random selection would leave some target rules at zero hits by chance.
    """

    def __init__(self, rules_file: str, match_ratio: float):
        self.match_ratio = match_ratio
        self.targets = []       # rules to match (traffic will be generated)
        self.skipped = []       # rules intentionally skipped (unused rule candidates)
        self._cycle: list[dict] = []   # current shuffled pass through targets

        if Path(rules_file).exists():
            with open(rules_file) as f:
                data = json.load(f)
            policies = data.get("policies", [])
            random.shuffle(policies)
            n_match = int(len(policies) * match_ratio)
            self.targets = policies[:n_match]
            self.skipped = policies[n_match:]
            log.info(f"Loaded {len(policies)} rules — targeting {n_match} ({match_ratio*100:.0f}%)")
        else:
            log.warning(f"Rules file not found: {rules_file}. Using fallback random targets.")

    def get_next_target(self) -> Optional[dict]:
        """
        Return the next policy in a round-robin cycle over the target set.
        When all targets have been served once, reshuffle and start a new pass.
        """
        if not self.targets:
            return None
        if not self._cycle:
            self._cycle = self.targets.copy()
            random.shuffle(self._cycle)
        return self._cycle.pop()


# ---------------------------------------------------------------------------
# Scapy-based packet generators
# ---------------------------------------------------------------------------

def _send_tcp_syn(src_ip: str, dst_ip: str, dst_port: int, iface: str):
    """Send a single TCP SYN packet."""
    try:
        from scapy.all import IP, TCP, send
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=dst_port,
            flags="S",
            seq=random.randint(1000, 9999999),
        )
        send(pkt, iface=iface, verbose=False)
        return True
    except Exception as e:
        log.debug(f"TCP SYN {src_ip}->{dst_ip}:{dst_port} failed: {e}")
        return False


def _send_icmp(src_ip: str, dst_ip: str, count: int, iface: str):
    """Send ICMP echo requests."""
    try:
        from scapy.all import IP, ICMP, send
        pkts = [
            IP(src=src_ip, dst=dst_ip) / ICMP(id=random.randint(1, 65535), seq=i)
            for i in range(count)
        ]
        send(pkts, iface=iface, verbose=False, inter=0.1)
        return True
    except Exception as e:
        log.debug(f"ICMP {src_ip}->{dst_ip} failed: {e}")
        return False


def _send_dns_query(src_ip: str, dst_ip: str, iface: str):
    """Send a DNS query (UDP 53)."""
    try:
        from scapy.all import IP, UDP, DNS, DNSQR, send
        domains = ["example.com", "test.local", "lab.internal",
                   "health.check", "api.service.local"]
        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=random.choice(domains)))
        )
        send(pkt, iface=iface, verbose=False)
        return True
    except Exception as e:
        log.debug(f"DNS {src_ip}->{dst_ip} failed: {e}")
        return False


def _send_http_request(src_ip: str, dst_ip: str, port: int, iface: str):
    """
    Send an HTTP GET using raw socket (bypasses Scapy for layer 7).
    Binds to src_ip explicitly.
    """
    paths = ["/", "/index.html", "/api/status", "/health", "/robots.txt"]
    path = random.choice(paths)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.bind((src_ip, 0))
        sock.connect((dst_ip, port))
        request = f"GET {path} HTTP/1.0\r\nHost: {dst_ip}\r\nUser-Agent: LabTraffic/1.0\r\n\r\n"
        sock.send(request.encode())
        try:
            sock.recv(512)
        except Exception:
            pass
        sock.close()
        return True
    except Exception as e:
        log.debug(f"HTTP {src_ip}->{dst_ip}:{port}{path} failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Session dispatcher
# ---------------------------------------------------------------------------

# Keys must match the service names used in phase1_rule_gen.py SERVICES list exactly.
SERVICE_PORT_MAP = {
    "HTTP":     ("tcp",      80),
    "HTTPS":    ("tcp",      443),
    "SSH":      ("tcp",      22),
    "DNS":      ("dns",      53),    # phase1 uses "DNS" (UDP 53)
    "SMTP":     ("tcp",      25),
    "MYSQL":    ("tcp",      3306),
    "RDP":      ("tcp",      3389),
    "FTP":      ("tcp",      21),
    "NTP":      ("udp_skip", 123),   # complex — skip generation
    "SNMP":     ("udp_skip", 161),   # complex — skip generation
    "PING":     ("icmp",     0),     # phase1 uses "PING" not "ICMP"
    "LDAP":     ("tcp",      389),
    "MS-SQL":   ("tcp",      1433),  # phase1 uses "MS-SQL" not "MSSQL"
    "IMAP":     ("tcp",      143),
    "POP3":     ("tcp",      110),
    "TELNET":   ("tcp",      23),
    "KERBEROS": ("tcp",      88),
    "NFS":      ("tcp",      2049),
    "RADIUS":   ("udp_skip", 1812),  # complex — skip generation
    "SYSLOG":   ("udp_skip", 514),   # complex — skip generation
}


def _addr_name_to_cidr(addr_name: str) -> Optional[str]:
    """
    Parse a LAB address object name back to its CIDR.
    LAB-NET-192-168-1-0_24  → 192.168.1.0/24
    LAB-SUB-192-168-1-176_28 → 192.168.1.176/28
    LAB-HOST-192-168-1-10   → 192.168.1.10/32
    Returns None if the name doesn't match any known pattern.
    """
    for prefix in ("LAB-NET-", "LAB-SUB-", "LAB-HOST-"):
        if addr_name.startswith(prefix):
            rest = addr_name[len(prefix):]
            if "_" in rest:
                ip_part, prefix_len = rest.rsplit("_", 1)
                return f"{ip_part.replace('-', '.')}/{prefix_len}"
            else:
                return f"{rest.replace('-', '.')}/32"
    return None


def _pick_ip_for_addr(addr_name: str, available_ips: list[str]) -> str:
    """
    Return an IP from available_ips that falls inside the address object's subnet.
    Falls back to a random available IP if no match (e.g. unknown address format).
    """
    cidr = _addr_name_to_cidr(addr_name)
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            matching = [ip for ip in available_ips if ipaddress.ip_address(ip) in net]
            if matching:
                return random.choice(matching)
        except ValueError:
            pass
    return random.choice(available_ips)


def dispatch_session(
    policy: dict,
    src_ips: list[str],
    dst_ips: list[str],
    iface: str,
    icmp_count: int,
) -> dict:
    """
    Generate traffic for one policy entry.
    Picks src/dst IPs that actually fall within the policy's address objects
    so the FortiGate hit counter increments on the correct rule.
    Returns a session record for statistics.
    """
    src_addr_name = (policy.get("srcaddr") or [{}])[0].get("name", "")
    dst_addr_name = (policy.get("dstaddr") or [{}])[0].get("name", "")
    src_ip = _pick_ip_for_addr(src_addr_name, src_ips)
    dst_ip = _pick_ip_for_addr(dst_addr_name, dst_ips)

    # Determine service from policy
    services = policy.get("service", [{}])
    svc_name = services[0].get("name", "HTTP") if services else "HTTP"
    svc_key = svc_name  # names now match SERVICE_PORT_MAP keys directly

    proto_info = SERVICE_PORT_MAP.get(svc_key, ("tcp", 80))
    proto, port = proto_info

    sent = False
    if proto == "icmp":
        sent = _send_icmp(src_ip, dst_ip, icmp_count, iface)
    elif proto == "dns":
        sent = _send_dns_query(src_ip, dst_ip, iface)
    elif proto == "tcp" and port in (80, 8080):
        sent = _send_http_request(src_ip, dst_ip, port, iface)
    elif proto == "tcp":
        sent = _send_tcp_syn(src_ip, dst_ip, port, iface)
    else:
        # udp_skip — not generating (would require complex handling)
        sent = False

    return {
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto,
        "port": port,
        "policy": policy.get("name", "unknown"),
        "sent": sent,
    }


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------

class TrafficStats:
    def __init__(self):
        self.sent       = 0
        self.failed     = 0
        self.sessions   = 0
        self.proto_counts: dict[str, int] = {}
        self.start_time = time.time()

    def record(self, session: dict):
        self.sessions += 1
        if session["sent"]:
            self.sent += 1
            proto = session["proto"]
            self.proto_counts[proto] = self.proto_counts.get(proto, 0) + 1
        else:
            self.failed += 1

    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        return f"{secs // 60}m {secs % 60}s"

    def render_table(self) -> Table:
        t = Table(title="Traffic Generation — Live Stats", show_lines=True)
        t.add_column("Metric", style="cyan")
        t.add_column("Value", style="green")
        t.add_row("Sessions",     str(self.sessions))
        t.add_row("Sent OK",      str(self.sent))
        t.add_row("Failed",       str(self.failed))
        t.add_row("Elapsed",      self.elapsed())
        for proto, cnt in self.proto_counts.items():
            t.add_row(f"  {proto.upper()}", str(cnt))
        return t


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(config_path: str, direction: str = "in2out", max_sessions: int = 0):
    """
    direction: 'in2out' | 'out2in' | 'both'
    max_sessions: 0 = run until SIGINT
    """
    global _STOP
    _STOP = False

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    net_cfg     = cfg["network"]
    traffic_cfg = cfg["traffic"]
    lab_cfg     = cfg["lab"]

    inside_ips  = [net_cfg["inside"]["primary_ip"]]  + net_cfg["inside"]["aliases"]
    outside_ips = [net_cfg["outside"]["primary_ip"]] + net_cfg["outside"]["aliases"]
    inside_iface  = net_cfg["inside"]["linux_interface"]
    outside_iface = net_cfg["outside"]["linux_interface"]

    rules_file = str(Path(lab_cfg["output_dir"]) / lab_cfg["rules_backup_file"])
    selector = TrafficTargetSelector(rules_file, traffic_cfg["match_ratio"])

    if not selector.targets:
        # Fallback: generate random traffic without rule file
        log.warning("No rule file found — generating generic random traffic.")

    # Default to 2 full passes through the target set so every targeted rule
    # gets at least 2 hits without running indefinitely. Caller can override
    # with --sessions N (0 = unlimited, run until Ctrl+C).
    if max_sessions == 0 and selector.targets:
        max_sessions = len(selector.targets) * 2
        console.print(
            f"[dim]Auto-stop after {max_sessions} sessions "
            f"(2 passes × {len(selector.targets)} targets). "
            "Use --sessions 0 to run indefinitely.[/dim]"
        )

    icmp_count = traffic_cfg.get("icmp_count", 3)
    delay_pkt  = traffic_cfg.get("inter_packet_delay", 0.5)
    delay_sess = traffic_cfg.get("inter_session_delay", 1.0)

    # Detect which side this host is on by checking local interfaces.
    # All generated rules are inside→outside, so out2in traffic won't match
    # any rule and requires LinuxB. Warn and skip out2in if running on LinuxA.
    import subprocess
    _local_addrs = subprocess.run(["ip", "addr"], capture_output=True, text=True).stdout
    on_inside  = net_cfg["inside"]["primary_ip"]  in _local_addrs
    on_outside = net_cfg["outside"]["primary_ip"] in _local_addrs

    if direction == "out2in" and on_inside and not on_outside:
        console.print(
            "[bold red]ERROR: --direction out2in requires LinuxB (outside host).\n"
            "All generated rules are inside→outside. Run --direction in2out from LinuxA."
        )
        return
    if direction == "both" and on_inside and not on_outside:
        console.print(
            "[yellow]WARNING: Running on LinuxA (inside host). "
            "'both' reduced to 'in2out' — no out2in rules exist to match.\n"
        )
        direction = "in2out"

    console.rule("[bold cyan]Phase 2 — Traffic Generation")
    console.print(f"Direction   : [bold]{direction}[/bold]")
    console.print(f"Inside IPs  : {inside_ips}")
    console.print(f"Outside IPs : {outside_ips}")
    console.print(f"Match ratio : {traffic_cfg['match_ratio']*100:.0f}%")
    console.print(f"Max sessions: {'unlimited' if max_sessions == 0 else max_sessions}")
    console.print(f"Press Ctrl+C to stop.\n")

    stats = TrafficStats()
    session_count = 0

    with Live(stats.render_table(), refresh_per_second=2, console=console) as live:
        while not _STOP:
            if max_sessions > 0 and session_count >= max_sessions:
                break

            policy = selector.get_next_target()
            if policy is None:
                # No rule file — synthesize a random target
                policy = {
                    "name": "RANDOM",
                    "service": [{"name": random.choice(["HTTP", "ICMP", "DNS-UDP", "HTTPS"])}],
                }

            if direction in ("in2out", "both"):
                result = dispatch_session(policy, inside_ips, outside_ips,
                                          inside_iface, icmp_count)
                stats.record(result)
                time.sleep(delay_pkt)

            if direction in ("out2in", "both"):
                result = dispatch_session(policy, outside_ips, inside_ips,
                                          outside_iface, icmp_count)
                stats.record(result)
                time.sleep(delay_pkt)

            session_count += 1
            live.update(stats.render_table())
            time.sleep(delay_sess)

    console.print(f"\n[green]Traffic generation stopped.")
    console.print(f"Total sessions: {stats.sessions} | Sent: {stats.sent} | Failed: {stats.failed}")


def setup_aliases(config_path: str, remove: bool = False):
    """Add or remove IP aliases on the local interface."""
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    net = cfg["network"]
    # Determine which side we're on by checking primary IPs reachable locally
    import subprocess
    result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
    addr_output = result.stdout

    if net["inside"]["primary_ip"] in addr_output:
        side = "inside"
    elif net["outside"]["primary_ip"] in addr_output:
        side = "outside"
    else:
        console.print("[red]Cannot detect which side (inside/outside) this host is.")
        return

    iface   = net[side]["linux_interface"]
    aliases = net[side]["aliases"]
    setup_ip_aliases(iface, aliases, remove=remove)
    console.print(f"[green]{'Removed' if remove else 'Added'} {len(aliases)} IP aliases on {iface} ({side})")


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--config",    default="config.yaml", help="Path to config.yaml")
    @click.option("--direction", default="in2out",
                  type=click.Choice(["in2out", "out2in", "both"]))
    @click.option("--sessions",  default=0,  help="Max sessions (0=unlimited)")
    @click.option("--setup-aliases",   is_flag=True, help="Add IP aliases and exit")
    @click.option("--remove-aliases",  is_flag=True, help="Remove IP aliases and exit")
    def main(config, direction, sessions, setup_aliases, remove_aliases):
        logging.basicConfig(level=logging.INFO)
        if setup_aliases:
            setup_aliases(config, remove=False)
        elif remove_aliases:
            setup_aliases(config, remove=True)
        else:
            run(config, direction, sessions)

    main()
