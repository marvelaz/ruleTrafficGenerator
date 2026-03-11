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
    {"name": "DNS-UDP",  "protocol": "UDP", "dst_port": "53"},
    {"name": "DNS-TCP",  "protocol": "TCP", "dst_port": "53"},
    {"name": "SMTP",     "protocol": "TCP", "dst_port": "25"},
    {"name": "MYSQL",    "protocol": "TCP", "dst_port": "3306"},
    {"name": "RDP",      "protocol": "TCP", "dst_port": "3389"},
    {"name": "HTTP-ALT", "protocol": "TCP", "dst_port": "8080"},
    {"name": "HTTPS-ALT","protocol": "TCP", "dst_port": "8443"},
    {"name": "FTP",      "protocol": "TCP", "dst_port": "21"},
    {"name": "NTP",      "protocol": "UDP", "dst_port": "123"},
    {"name": "SNMP",     "protocol": "UDP", "dst_port": "161"},
    {"name": "ICMP",     "protocol": "ICMP","dst_port": None},
    {"name": "LDAP",     "protocol": "TCP", "dst_port": "389"},
    {"name": "LDAPS",    "protocol": "TCP", "dst_port": "636"},
    {"name": "MSSQL",    "protocol": "TCP", "dst_port": "1433"},
    {"name": "ORACLE",   "protocol": "TCP", "dst_port": "1521"},
    {"name": "REDIS",    "protocol": "TCP", "dst_port": "6379"},
    {"name": "MONGO",    "protocol": "TCP", "dst_port": "27017"},
]

INSIDE_SUBNETS = [
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.10.0/24",
    "172.16.0.0/24",
    "172.16.1.0/24",
]

OUTSIDE_SUBNETS = [
    "10.10.0.0/24",
    "10.10.1.0/24",
    "10.20.0.0/24",
    "10.30.0.0/24",
    "10.40.0.0/24",
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
# Address + Service Object Builder
# ---------------------------------------------------------------------------

def _cidr_to_fgt(cidr: str) -> str:
    """Convert 192.168.1.0/24 to FortiGate format 192.168.1.0 255.255.255.0"""
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.netmask}"


def build_address_pool(n_rules: int) -> list[dict]:
    """
    Generate a pool of address objects covering:
    - Full /24 subnets (broad)
    - /28 subnets within those /24s (medium)
    - /32 host addresses (narrow, for overlap with broader rules)
    """
    addresses = []
    seen = set()

    # Broad /24 subnets
    for subnet in INSIDE_SUBNETS + OUTSIDE_SUBNETS:
        name = f"LAB-NET-{subnet.replace('/', '_').replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": subnet, "cidr": subnet})
            seen.add(name)

    # /28 subnets carved from /24s (for overlapping range overlap type)
    for base_subnet in INSIDE_SUBNETS + OUTSIDE_SUBNETS:
        net = ipaddress.ip_network(base_subnet, strict=False)
        subnets_28 = list(net.subnets(new_prefix=28))
        for sub in random.sample(subnets_28, min(4, len(subnets_28))):
            cidr = str(sub)
            name = f"LAB-SUB-{cidr.replace('/', '_').replace('.', '-')}"
            if name not in seen:
                addresses.append({"name": name, "subnet": cidr, "cidr": cidr})
                seen.add(name)

    # /32 hosts (for shadow rules and overlapping with /24 or /28)
    sample_hosts = [
        "192.168.1.10", "192.168.1.20", "192.168.1.50",
        "192.168.2.10", "192.168.2.20",
        "10.10.0.10",   "10.10.0.20",   "10.10.0.50",
        "10.10.1.10",   "10.20.0.5",
    ]
    for host in sample_hosts:
        cidr = f"{host}/32"
        name = f"LAB-HOST-{host.replace('.', '-')}"
        if name not in seen:
            addresses.append({"name": name, "subnet": cidr, "cidr": cidr})
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
    action: str = "accept",
    comment: str = "",
) -> dict:
    return {
        "name": name,
        "srcintf": [{"name": "any"}],
        "dstintf": [{"name": "any"}],
        "srcaddr": [{"name": src_addr}],
        "dstaddr": [{"name": dst_addr}],
        "service": [{"name": service}],
        "action": action,
        "status": "enable",
        "logtraffic": "all",
        "logtraffic-start": "enable",
        "comments": f"{TAG} seq={seq} {comment}".strip(),
        "nat": "disable",
    }


def generate_policies(n: int, address_pool: list[dict]) -> tuple[list[dict], dict]:
    """
    Generate n policies with deliberate overlap patterns.
    Returns (policies list, metadata dict with overlap stats).
    """
    policies = []
    metadata = {
        "total": n,
        "clean": 0,
        "shadow": 0,
        "duplicate": 0,
        "subnet_overlap": 0,
        "service_overlap": 0,
    }

    # Separate broad vs narrow address objects
    broad = [a for a in address_pool if "/" in a["cidr"] and
             int(a["cidr"].split("/")[1]) <= 24]
    narrow = [a for a in address_pool if "/" in a["cidr"] and
              int(a["cidr"].split("/")[1]) > 24]
    hosts = [a for a in address_pool if a["cidr"].endswith("/32")]

    inside_broad  = [a for a in broad if any(a["cidr"].startswith(p)
                     for p in ["192.168.", "172.16."])]
    outside_broad = [a for a in broad if a["cidr"].startswith("10.")]
    inside_narrow = [a for a in narrow if any(a["cidr"].startswith(p)
                     for p in ["192.168.", "172.16."])]
    outside_narrow= [a for a in narrow if a["cidr"].startswith("10.")]
    inside_hosts  = [a for a in hosts if any(a["cidr"].startswith(p)
                     for p in ["192.168.", "172.16."])]
    outside_hosts = [a for a in hosts if a["cidr"].startswith("10.")]

    # Fallback if lists are too short
    if not inside_broad:  inside_broad  = address_pool[:3]
    if not outside_broad: outside_broad = address_pool[3:6]
    if not inside_narrow: inside_narrow = inside_broad
    if not outside_narrow:outside_narrow= outside_broad
    if not inside_hosts:  inside_hosts  = inside_narrow
    if not outside_hosts: outside_hosts = outside_narrow

    # Determine overlap distribution
    # Clean: ~35%, Shadow: ~20%, Duplicate: ~15%, SubnetOverlap: ~15%, SvcOverlap: ~15%
    n_clean   = int(n * 0.35)
    n_shadow  = int(n * 0.20)
    n_dup     = int(n * 0.15)
    n_subnet  = int(n * 0.15)
    n_svc     = n - n_clean - n_shadow - n_dup - n_subnet

    seq = 1

    # --- Clean rules ---
    for i in range(n_clean):
        src = random.choice(inside_broad + inside_narrow)
        dst = random.choice(outside_broad + outside_narrow)
        svc = random.choice(SERVICES)
        name = f"LAB-CLEAN-{seq:04d}"
        policies.append(_make_policy(seq, name, src["name"], dst["name"],
                                     svc["name"], comment="type=clean"))
        metadata["clean"] += 1
        seq += 1

    # --- Shadow rules ---
    # First insert a broad ANY-like rule, then insert a narrower rule after it
    for i in range(n_shadow):
        src_broad = random.choice(inside_broad)
        dst_broad = random.choice(outside_broad)
        svc = random.choice(SERVICES)

        # Broad rule (will shadow the specific one placed after)
        name_broad = f"LAB-BROAD-{seq:04d}"
        policies.append(_make_policy(seq, name_broad, src_broad["name"], dst_broad["name"],
                                     svc["name"], comment="type=shadow-broad"))
        seq += 1

        # Narrow rule — shadowed by the broad rule above
        src_narrow = random.choice(inside_hosts + inside_narrow)
        dst_narrow = random.choice(outside_hosts + outside_narrow)
        name_narrow = f"LAB-SHADOW-{seq:04d}"
        policies.append(_make_policy(seq, name_narrow, src_narrow["name"], dst_narrow["name"],
                                     svc["name"], comment="type=shadow-specific"))
        metadata["shadow"] += 1
        seq += 1

    # --- Duplicate rules (same logic, different name) ---
    for i in range(n_dup):
        src = random.choice(inside_broad)
        dst = random.choice(outside_broad)
        svc = random.choice(SERVICES)
        name_a = f"LAB-DUP-A-{seq:04d}"
        policies.append(_make_policy(seq, name_a, src["name"], dst["name"],
                                     svc["name"], comment="type=duplicate"))
        seq += 1
        name_b = f"LAB-DUP-B-{seq:04d}"
        policies.append(_make_policy(seq, name_b, src["name"], dst["name"],
                                     svc["name"], comment="type=duplicate"))
        metadata["duplicate"] += 1
        seq += 1

    # --- Overlapping subnet ranges ---
    # /24 rule + /28 or /32 rule covering same space
    for i in range(n_subnet):
        src_broad  = random.choice(inside_broad)
        src_narrow = random.choice(inside_narrow + inside_hosts)
        dst = random.choice(outside_broad)
        svc = random.choice(SERVICES)
        name_wide = f"LAB-WIDE-{seq:04d}"
        policies.append(_make_policy(seq, name_wide, src_broad["name"], dst["name"],
                                     svc["name"], comment="type=subnet-overlap-broad"))
        seq += 1
        name_spec = f"LAB-SPEC-{seq:04d}"
        policies.append(_make_policy(seq, name_spec, src_narrow["name"], dst["name"],
                                     svc["name"], comment="type=subnet-overlap-specific"))
        metadata["subnet_overlap"] += 1
        seq += 1

    # --- Same src/dst, different services (collapsible) ---
    for i in range(n_svc):
        src = random.choice(inside_broad)
        dst = random.choice(outside_broad)
        svcs = random.sample(SERVICES, k=random.randint(2, 4))
        for svc in svcs:
            name = f"LAB-MSVC-{seq:04d}"
            policies.append(_make_policy(seq, name, src["name"], dst["name"],
                                         svc["name"], comment="type=svc-overlap"))
            seq += 1
        metadata["service_overlap"] += 1

    # Shuffle to distribute overlap types throughout the policy list
    # (makes it less obvious during manual inspection)
    random.shuffle(policies)

    # Re-number names after shuffle for stable reference
    for idx, p in enumerate(policies):
        p["_seq"] = idx + 1  # internal reference only

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

    console.rule("[bold cyan]Phase 1 — Rule Generation")
    console.print(f"Target rule count : [bold]{n_rules}[/bold]")
    console.print(f"FortiGate         : [bold]{cfg['fortigate']['host']}[/bold]")
    console.print(f"VDOM              : [bold]{cfg['fortigate']['vdom']}[/bold]")
    console.print(f"Dry run           : [bold]{dry_run}[/bold]")

    # Build address pool
    console.print("\n[cyan]Building address pool...")
    address_pool = build_address_pool(n_rules)
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

        # Push custom service objects
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console) as progress:
            task = progress.add_task("Pushing service objects...", total=len(SERVICES))
            for svc in SERVICES:
                svc_name = f"LAB-SVC-{svc['name']}"
                if svc_name not in existing_svcs:
                    api.create_service(svc_name, svc)
                    time.sleep(0.05)
                progress.advance(task)

        # Update service names in pool to use lab-prefixed names
        for svc in SERVICES:
            svc["name"] = f"LAB-SVC-{svc['name']}"

    # Generate policies
    console.print("\n[cyan]Generating policy objects...")
    policies, metadata = generate_policies(n_rules, address_pool)
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
