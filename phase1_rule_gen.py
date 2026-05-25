"""
Phase 1 — Rule Generation
Generates N firewall policies via FortiGate REST API with deliberate
overlap patterns to simulate real-world configuration drift.

Overlap types injected:
  - Shadow rules (unreachable due to prior broader match)
  - Duplicate rules with different names
  - Overlapping subnet ranges (/24 containing /32s or /28s)
  - Same src/dst, different services (collapsible into service group)

All policies tagged with LAB-TEST-2025 in comments.
"""

import json
import random
import time
import logging
import ipaddress
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVICES = [
    {"name": "HTTP",     "protocol": "TCP", "dst_port": "80"},
    {"name": "HTTPS",    "protocol": "TCP", "dst_port": "443"},
    {"name": "SSH",      "protocol": "TCP", "dst_port": "22"},
    {"name": "DNS",      "protocol": "UDP", "dst_port": "53"},
    {"name": "SMTP",     "protocol": "TCP", "dst_port": "25"},
    {"name": "MYSQL",    "protocol": "TCP", "dst_port": "3306"},
    {"name": "RDP",      "protocol": "TCP", "dst_port": "3389"},
    {"name": "FTP",      "protocol": "TCP", "dst_port": "21"},
    {"name": "NTP",      "protocol": "UDP", "dst_port": "123"},
    {"name": "SNMP",     "protocol": "UDP", "dst_port": "161"},
    {"name": "PING",     "protocol": "ICMP","dst_port": None},
    {"name": "LDAP",     "protocol": "TCP", "dst_port": "389"},
    {"name": "MS-SQL",   "protocol": "TCP", "dst_port": "1433"},
    {"name": "IMAP",     "protocol": "TCP", "dst_port": "143"},
    {"name": "POP3",     "protocol": "TCP", "dst_port": "110"},
    {"name": "TELNET",   "protocol": "TCP", "dst_port": "23"},
    {"name": "KERBEROS", "protocol": "TCP", "dst_port": "88"},
    {"name": "NFS",      "protocol": "TCP", "dst_port": "2049"},
    {"name": "RADIUS",   "protocol": "UDP", "dst_port": "1812"},
    {"name": "SYSLOG",   "protocol": "UDP", "dst_port": "514"},
]

TAG = "LAB-TEST-2025"


# ---------------------------------------------------------------------------
# FortiGate API Client
# ---------------------------------------------------------------------------

class FortiGateAPI:
    def __init__(self, cfg: dict):
        self.base = f"https://{cfg['host']}:{cfg['port']}/api/v2"
        self.token = cfg["api_token"]
        self.vdom = cfg["vdom"]
        self.verify = cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _url(self, path: str) -> str:
        return f"{self.base}{path}?vdom={self.vdom}"

    def get(self, path: str) -> dict:
        r = self.session.get(self._url(path), verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, data: dict) -> dict:
        r = self.session.post(self._url(path), json=data, verify=self.verify, timeout=self.timeout)
        if r.status_code not in (200, 201):
            log.error(f"POST {path} failed {r.status_code}: {r.text[:300]}")
            r.raise_for_status()
        return r.json()

    def delete(self, path: str) -> dict:
        r = self.session.delete(self._url(path), verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_existing_addresses(self) -> set:
        """Return set of existing address object names to avoid collisions."""
        try:
            resp = self.get("/cmdb/firewall/address")
            return {obj["name"] for obj in resp.get("results", [])}
        except Exception:
            return set()

    def get_existing_services(self) -> set:
        """Return set of existing custom service names."""
        try:
            resp = self.get("/cmdb/firewall.service/custom")
            return {obj["name"] for obj in resp.get("results", [])}
        except Exception:
            return set()

    def create_address(self, name: str, subnet: str) -> bool:
        """Create a firewall address object. Returns True on success."""
        try:
            self.post("/cmdb/firewall/address", {
                "name": name,
                "type": "ipmask",
                "subnet": subnet,
                "comment": TAG,
            })
            return True
        except Exception as e:
            log.debug(f"Address {name} may already exist: {e}")
            return False

    def create_service(self, name: str, svc: dict) -> bool:
        """Create a custom service object."""
        try:
            body: dict[str, Any] = {
                "name": name,
                "comment": TAG,
            }
            if svc["protocol"] == "TCP":
                body["protocol"] = "TCP/UDP/SCTP"
                body["tcp-portrange"] = svc["dst_port"]
            elif svc["protocol"] == "UDP":
                body["protocol"] = "TCP/UDP/SCTP"
                body["udp-portrange"] = svc["dst_port"]
            elif svc["protocol"] == "ICMP":
                body["protocol"] = "ICMP"
            self.post("/cmdb/firewall.service/custom", body)
            return True
        except Exception as e:
            log.debug(f"Service {name} may already exist: {e}")
            return False

    def create_policy(self, policy: dict) -> bool:
        """Push a single firewall policy."""
        try:
            self.post("/cmdb/firewall/policy", policy)
            return True
        except Exception as e:
            log.error(f"Failed to create policy {policy.get('name')}: {e}")
            return False

    def delete_policy(self, policy_id: int) -> bool:
        try:
            self.delete(f"/cmdb/firewall/policy/{policy_id}")
            return True
        except Exception as e:
            log.error(f"Failed to delete policy {policy_id}: {e}")
            return False

    def get_all_lab_policies(self) -> list:
        """Return all policies tagged with LAB-TEST-2025."""
        try:
            resp = self.get("/cmdb/firewall/policy")
            return [
                p for p in resp.get("results", [])
                if TAG in p.get("comments", "")
            ]
        except Exception as e:
            log.error(f"Failed to fetch policies: {e}")
            return []


# ---------------------------------------------------------------------------
# Policy name generator
# ---------------------------------------------------------------------------

_SVC_ABBREV: dict[str, str] = {
    "HTTP":     "WEB",
    "HTTPS":    "WEBS",
    "SSH":      "SSH",
    "DNS":      "DNS",
    "SMTP":     "MAIL",
    "MYSQL":    "DB",
    "RDP":      "RDP",
    "FTP":      "FTP",
    "NTP":      "NTP",
    "SNMP":     "MGMT",
    "PING":     "PING",
    "LDAP":     "LDAP",
    "MS-SQL":   "SQL",
    "IMAP":     "IMAP",
    "POP3":     "POP3",
    "TELNET":   "TEL",
    "KERBEROS": "AUTH",
    "NFS":      "NFS",
    "RADIUS":   "AUTH",
    "SYSLOG":   "LOG",
}


def _rule_name(src_addr: str, dst_addr: str, svc_name: str, counter: int) -> str:
    """
    Generate a realistic-looking policy name from zone + service + counter.
    Reveals nothing about overlap type — looks like an admin-authored rule.
    Examples: CORP-INET-WEB-0042, MGMT-WAN-SSH-0017
    """
    if "192-168" in src_addr:
        src_zone = "CORP"
    elif "172-16" in src_addr:
        src_zone = "MGMT"
    else:
        src_zone = "LAN"

    if "10-10" in dst_addr:
        dst_zone = "INET"
    elif any(x in dst_addr for x in ("10-20", "10-30", "10-40")):
        dst_zone = "WAN"
    else:
        dst_zone = "EXT"

    svc = _SVC_ABBREV.get(svc_name, svc_name[:4].upper())
    return f"{src_zone}-{dst_zone}-{svc}-{counter:04d}"


# ---------------------------------------------------------------------------
# Address + Service Object Builder
# ---------------------------------------------------------------------------

def _cidr_to_fgt(cidr: str) -> str:
    """Convert 192.168.1.0/24 to FortiGate format 192.168.1.0 255.255.255.0"""
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.netmask}"


def build_address_pool(n_rules: int, cfg: dict) -> list[dict]:
    """
    Generate a pool of address objects covering:
    - Full subnets from config (broad)
    - /28 subnets carved from those (medium)
    - /32 host addresses from configured primary IPs and aliases (narrow)

    Subnets and hosts are read from config so the address pool is always
    constrained to IPs reachable from the Linux hosts — required in cloud
    environments where anti-spoofing drops traffic to/from unrouted addresses.
    """
    inside_subnets  = cfg["network"]["inside"]["subnets"]
    outside_subnets = cfg["network"]["outside"]["subnets"]

    inside_host_ips = (
        [cfg["network"]["inside"]["primary_ip"]]
        + cfg["network"]["inside"].get("aliases", [])
    )
    outside_host_ips = (
        [cfg["network"]["outside"]["primary_ip"]]
        + cfg["network"]["outside"].get("aliases", [])
    )

    addresses = []
    seen = set()

    # Broad subnets from config
    for subnet in inside_subnets:
        name = f"LAB-NET-{subnet.replace('/', '_').replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": subnet, "cidr": subnet, "side": "inside"})
            seen.add(name)
    for subnet in outside_subnets:
        name = f"LAB-NET-{subnet.replace('/', '_').replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": subnet, "cidr": subnet, "side": "outside"})
            seen.add(name)

    # /28 subnets carved from configured subnets
    for subnet in inside_subnets:
        net = ipaddress.ip_network(subnet, strict=False)
        subnets_28 = list(net.subnets(new_prefix=28))
        for sub in random.sample(subnets_28, min(4, len(subnets_28))):
            cidr = str(sub)
            name = f"LAB-SUB-{cidr.replace('/', '_').replace('.', '-')}"
            if name not in seen:
                addresses.append({"name": name, "subnet": cidr, "cidr": cidr, "side": "inside"})
                seen.add(name)
    for subnet in outside_subnets:
        net = ipaddress.ip_network(subnet, strict=False)
        subnets_28 = list(net.subnets(new_prefix=28))
        for sub in random.sample(subnets_28, min(4, len(subnets_28))):
            cidr = str(sub)
            name = f"LAB-SUB-{cidr.replace('/', '_').replace('.', '-')}"
            if name not in seen:
                addresses.append({"name": name, "subnet": cidr, "cidr": cidr, "side": "outside"})
                seen.add(name)

    # /32 hosts from configured aliases — these are the actual IPs reachable on each host
    for ip in inside_host_ips:
        cidr = f"{ip}/32"
        name = f"LAB-HOST-{ip.replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": cidr, "cidr": cidr, "side": "inside"})
            seen.add(name)
    for ip in outside_host_ips:
        cidr = f"{ip}/32"
        name = f"LAB-HOST-{ip.replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": cidr, "cidr": cidr, "side": "outside"})
            seen.add(name)

    return addresses


# ---------------------------------------------------------------------------
# Policy Generator
# ---------------------------------------------------------------------------

def _make_policy(
    seq: int,
    name: str,
    src_addr: str,
    dst_addr: str,
    service: str,
    srcintf: str,
    dstintf: str,
    action: str = "accept",
    policy_type: str = "",
) -> dict:
    return {
        "name": name,
        "srcintf": [{"name": srcintf}],
        "dstintf": [{"name": dstintf}],
        "srcaddr": [{"name": src_addr}],
        "dstaddr": [{"name": dst_addr}],
        "service": [{"name": service}],
        "action": action,
        "schedule": "always",
        "status": "enable",
        "logtraffic": "utm",
        "logtraffic-start": "disable",
        "inspection-mode": "flow",
        "ssl-ssh-profile": "no-inspection",
        "profile-type": "single",
        "profile-protocol-options": "default",
        "utm-status": "disable",
        "match-vip": "enable",
        "comments": TAG,               # tag only — no type hint visible in FortiGate UI
        "nat": "disable",
        "_seq": seq,
        "_type": policy_type,          # internal only — stripped before API push
    }


def generate_policies(n: int, address_pool: list[dict], ratios: dict,
                      srcintf: str, dstintf: str) -> tuple[list[dict], dict]:
    """
    Generate exactly n policies with deliberate overlap patterns.

    ratios: dict with keys shadow, duplicate, subnet_overlap, service_overlap, clean.
            Values are relative weights (auto-normalized — don't need to sum to 1).
            clean always fills the remainder so the final count is exactly n.

    Policy-count math:
      shadow/duplicate/subnet_overlap each emit 2 policies per group.
      service_overlap emits 2–4 per group (capped to avoid overshoot).
      clean emits 1 per group and fills the gap to reach exactly n.
    """
    # Normalize ratios
    total_weight = sum(ratios.values())
    r = {k: v / total_weight for k, v in ratios.items()}

    policies = []
    metadata = {
        "total": n,
        "clean": 0,
        "shadow": 0,
        "duplicate": 0,
        "subnet_overlap": 0,
        "service_overlap": 0,
    }

    # Separate broad vs narrow address objects, categorised by side tag set in build_address_pool
    broad  = [a for a in address_pool if int(a["cidr"].split("/")[1]) <= 24]
    narrow = [a for a in address_pool if int(a["cidr"].split("/")[1]) > 24]
    hosts  = [a for a in address_pool if a["cidr"].endswith("/32")]

    inside_broad   = [a for a in broad  if a["side"] == "inside"]
    outside_broad  = [a for a in broad  if a["side"] == "outside"]
    inside_narrow  = [a for a in narrow if a["side"] == "inside"]
    outside_narrow = [a for a in narrow if a["side"] == "outside"]
    inside_hosts   = [a for a in hosts  if a["side"] == "inside"]
    outside_hosts  = [a for a in hosts  if a["side"] == "outside"]

    if not inside_broad:   inside_broad   = address_pool[:3]
    if not outside_broad:  outside_broad  = address_pool[3:6]
    if not inside_narrow:  inside_narrow  = inside_broad
    if not outside_narrow: outside_narrow = outside_broad
    if not inside_hosts:   inside_hosts   = inside_narrow
    if not outside_hosts:  outside_hosts  = outside_narrow

    seq = 1

    # Target policy counts per type (not iteration counts).
    # shadow/dup/subnet each need an even number (2 policies per group).
    # service_overlap target is filled exactly by capping the last group.
    # clean fills whatever remains to reach exactly n.
    n_shadow_target  = round(n * r["shadow"])  & ~1   # round to even
    n_dup_target     = round(n * r["duplicate"]) & ~1
    n_subnet_target  = round(n * r["subnet_overlap"]) & ~1
    n_svc_target     = round(n * r["service_overlap"])

    # --- Shadow rules (2 per group: broad + unreachable narrow) ---
    for _ in range(n_shadow_target // 2):
        src_broad = random.choice(inside_broad)
        dst_broad = random.choice(outside_broad)
        svc = random.choice(SERVICES)
        policies.append(_make_policy(seq,
                                     _rule_name(src_broad["name"], dst_broad["name"], svc["name"], seq),
                                     src_broad["name"], dst_broad["name"],
                                     svc["name"], srcintf, dstintf, policy_type="shadow-broad"))
        seq += 1
        src_narrow = random.choice(inside_hosts + inside_narrow)
        dst_narrow = random.choice(outside_hosts + outside_narrow)
        policies.append(_make_policy(seq,
                                     _rule_name(src_narrow["name"], dst_narrow["name"], svc["name"], seq),
                                     src_narrow["name"], dst_narrow["name"],
                                     svc["name"], srcintf, dstintf, policy_type="shadow-specific"))
        metadata["shadow"] += 1
        seq += 1

    # --- Duplicate rules (2 per group: identical match criteria, different names) ---
    for _ in range(n_dup_target // 2):
        src = random.choice(inside_broad)
        dst = random.choice(outside_broad)
        svc = random.choice(SERVICES)
        policies.append(_make_policy(seq,
                                     _rule_name(src["name"], dst["name"], svc["name"], seq),
                                     src["name"], dst["name"],
                                     svc["name"], srcintf, dstintf, policy_type="duplicate"))
        seq += 1
        policies.append(_make_policy(seq,
                                     _rule_name(src["name"], dst["name"], svc["name"], seq),
                                     src["name"], dst["name"],
                                     svc["name"], srcintf, dstintf, policy_type="duplicate"))
        metadata["duplicate"] += 1
        seq += 1

    # --- Subnet overlap rules (2 per group: /24 broad + /28 or /32 specific) ---
    for _ in range(n_subnet_target // 2):
        src_broad  = random.choice(inside_broad)
        src_narrow = random.choice(inside_narrow + inside_hosts)
        dst = random.choice(outside_broad)
        svc = random.choice(SERVICES)
        policies.append(_make_policy(seq,
                                     _rule_name(src_broad["name"], dst["name"], svc["name"], seq),
                                     src_broad["name"], dst["name"],
                                     svc["name"], srcintf, dstintf, policy_type="subnet-overlap-broad"))
        seq += 1
        policies.append(_make_policy(seq,
                                     _rule_name(src_narrow["name"], dst["name"], svc["name"], seq),
                                     src_narrow["name"], dst["name"],
                                     svc["name"], srcintf, dstintf, policy_type="subnet-overlap-specific"))
        metadata["subnet_overlap"] += 1
        seq += 1

    # --- Service overlap rules (2–4 per group, capped to avoid overshoot) ---
    svc_count = 0
    while svc_count < n_svc_target:
        src = random.choice(inside_broad)
        dst = random.choice(outside_broad)
        k = min(random.randint(2, 4), n_svc_target - svc_count)
        for svc in random.sample(SERVICES, k=k):
            policies.append(_make_policy(seq,
                                         _rule_name(src["name"], dst["name"], svc["name"], seq),
                                         src["name"], dst["name"],
                                         svc["name"], srcintf, dstintf, policy_type="svc-overlap"))
            seq += 1
        svc_count += k
        metadata["service_overlap"] += 1

    # --- Clean rules — fill remainder to reach exactly n ---
    for _ in range(max(0, n - len(policies))):
        src = random.choice(inside_broad + inside_narrow)
        dst = random.choice(outside_broad + outside_narrow)
        svc = random.choice(SERVICES)
        policies.append(_make_policy(seq,
                                     _rule_name(src["name"], dst["name"], svc["name"], seq),
                                     src["name"], dst["name"],
                                     svc["name"], srcintf, dstintf, policy_type="clean"))
        metadata["clean"] += 1
        seq += 1

    # Shuffle to hide overlap patterns during manual inspection
    random.shuffle(policies)
    for idx, p in enumerate(policies):
        p["_seq"] = idx + 1

    metadata["total_pushed"] = len(policies)
    return policies, metadata


# ---------------------------------------------------------------------------
# Main Orchestration
# ---------------------------------------------------------------------------

def run(config_path: str, n_rules: int, dry_run: bool = False):
    """
    Main entry point for Phase 1.
    config_path: path to config.yaml
    n_rules: number of rules requested by user
    dry_run: if True, generate policies but do not push to FortiGate
    """
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    Path(cfg["lab"]["output_dir"]).mkdir(parents=True, exist_ok=True)

    api = FortiGateAPI(cfg["fortigate"])
    tag = cfg["lab"]["tag"]
    srcintf = cfg["fortigate"].get("inside_interface", "port2")
    dstintf = cfg["fortigate"].get("outside_interface", "port1")

    console.rule("[bold cyan]Phase 1 — Rule Generation")
    console.print(f"Target rule count : [bold]{n_rules}[/bold]")
    console.print(f"FortiGate         : [bold]{cfg['fortigate']['host']}[/bold]")
    console.print(f"VDOM              : [bold]{cfg['fortigate']['vdom']}[/bold]")
    console.print(f"Interfaces        : [bold]{srcintf}[/bold] (inside) → [bold]{dstintf}[/bold] (outside)")
    console.print(f"Dry run           : [bold]{dry_run}[/bold]")

    # Build address pool
    console.print("\n[cyan]Building address pool...")
    address_pool = build_address_pool(n_rules, cfg)
    console.print(f"  Address objects  : {len(address_pool)}")

    # Push address objects
    if not dry_run:
        existing_addrs = api.get_existing_addresses()
        existing_svcs  = api.get_existing_services()
        console.print(f"  Existing addresses on FGT: {len(existing_addrs)}")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console) as progress:
            task = progress.add_task("Pushing address objects...", total=len(address_pool))
            for addr in address_pool:
                if addr["name"] not in existing_addrs:
                    api.create_address(addr["name"], _cidr_to_fgt(addr["cidr"]))
                    time.sleep(0.05)
                progress.advance(task)

        # Use built-in FortiGate services directly (no custom service creation needed)
        console.print("  Using built-in FortiGate services")

    # Load ratios from config (with hardcoded defaults as fallback)
    ratios = cfg.get("rules", {}).get("ratios", {
        "shadow":          0.20,
        "duplicate":       0.15,
        "subnet_overlap":  0.15,
        "service_overlap": 0.15,
        "clean":           0.35,
    })

    # Generate policies
    console.print("\n[cyan]Generating policy objects...")
    policies, metadata = generate_policies(n_rules, address_pool, ratios, srcintf, dstintf)
    console.print(f"  Total policies generated : {len(policies)}")
    console.print(f"  Clean                    : {metadata['clean']}")
    console.print(f"  Shadow                   : {metadata['shadow']}")
    console.print(f"  Duplicate                : {metadata['duplicate']}")
    console.print(f"  Subnet overlap           : {metadata['subnet_overlap']}")
    console.print(f"  Service overlap          : {metadata['service_overlap']}")

    # Save generated policies to disk before pushing
    output_file = Path(cfg["lab"]["output_dir"]) / cfg["lab"]["rules_backup_file"]
    with open(output_file, "w") as f:
        json.dump({"metadata": metadata, "policies": policies}, f, indent=2)
    console.print(f"\n[green]Rules saved to {output_file}")

    if dry_run:
        console.print("\n[yellow]DRY RUN — skipping FortiGate API push.")
        return metadata

    # Push policies to FortiGate
    pushed = 0
    failed = 0
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  console=console) as progress:
        task = progress.add_task("Pushing policies to FortiGate...", total=len(policies))
        for policy in policies:
            # Remove internal tracking keys before pushing
            clean_policy = {k: v for k, v in policy.items() if not k.startswith("_")}
            if api.create_policy(clean_policy):
                pushed += 1
            else:
                failed += 1
            time.sleep(0.1)  # Rate limit — avoid overwhelming API
            progress.advance(task)

    console.print(f"\n[green]✓ Pushed  : {pushed}")
    if failed:
        console.print(f"[red]✗ Failed  : {failed}")

    metadata["pushed"] = pushed
    metadata["failed"] = failed
    return metadata


def delete_lab_rules(config_path: str):
    """Delete all policies tagged with LAB-TEST-2025 from FortiGate."""
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    api = FortiGateAPI(cfg["fortigate"])
    console.rule("[bold red]Deleting Lab Rules")

    lab_policies = api.get_all_lab_policies()
    console.print(f"Found {len(lab_policies)} lab policies to delete.")

    deleted = 0
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  console=console) as progress:
        task = progress.add_task("Deleting...", total=len(lab_policies))
        for p in lab_policies:
            if api.delete_policy(p["policyid"]):
                deleted += 1
            time.sleep(0.05)
            progress.advance(task)

    console.print(f"[green]Deleted {deleted} / {len(lab_policies)} lab policies.")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    run("config.yaml", n)
