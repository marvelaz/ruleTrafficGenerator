"""
phase3_traditional.py — Traditional (CIDR + Hit-count) Policy Analysis

Two detection passes run sequentially and produce a single combined report.

  Pass A — Behavioral  (skip with --skip-unused)
    Data source : FortiGate monitor API  GET /api/v2/monitor/firewall/policy
    Detects     : policies with hit_count == 0 (unused rules)
    Note        : requires traffic to have been generated first (phase2).
                  No FortiAnalyzer required.

  Pass B — Structural  (always runs)
    Data source : FortiGate CMDB policy list + address-object CIDR map
    Detects     : shadow rules, duplicate rules, subnet overlaps, collapsible
                  service groups — using ipaddress CIDR containment math
    Note        : no traffic required, no FAZ required.

Run phase3_zero.py first to get the ground truth, then compare counts.

Usage:
    python3 phase3_traditional.py
    python3 phase3_traditional.py --config config.yaml
    python3 phase3_traditional.py --output report.json
    python3 phase3_traditional.py --skip-unused           # structural analysis only
    python3 phase3_traditional.py --skip-unused --output report.json
"""

import ipaddress
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import click
import requests
import urllib3
import yaml
from rich.console import Console
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)
console = Console()

TAG = "LAB-TEST-2025"


# ---------------------------------------------------------------------------
# FortiGate API client
# ---------------------------------------------------------------------------

class FortiGateAPI:
    def __init__(self, cfg: dict):
        self.base    = f"https://{cfg['host']}:{cfg['port']}/api/v2"
        self.vdom    = cfg["vdom"]
        self.verify  = cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {cfg['api_token']}",
            "Content-Type":  "application/json",
        })

    def _url(self, path: str) -> str:
        sep = "?" if "?" not in path else "&"
        return f"{self.base}{path}{sep}vdom={self.vdom}"

    def get(self, path: str) -> dict:
        r = self.session.get(self._url(path), verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_policy_hitcounts(self) -> list[dict]:
        """GET /monitor/firewall/policy/ — per-policy hit counts."""
        try:
            resp = self.get("/monitor/firewall/policy/")
            results = resp.get("results", [])
            # FortiOS sometimes returns a dict keyed by policyid instead of a list
            if isinstance(results, dict):
                return [{"policyid": k, **v} for k, v in results.items()]
            return results
        except Exception as e:
            log.error(f"Hit-count query failed: {e}")
            return []

    def get_all_lab_policies(self) -> list[dict]:
        """Return all LAB-TEST-2025 tagged policies in FortiGate sequence order."""
        try:
            resp = self.get("/cmdb/firewall/policy")
            return [
                p for p in resp.get("results", [])
                if TAG in p.get("comments", "")
            ]
        except Exception as e:
            log.warning(f"Policy fetch failed: {e}")
            return []

    def get_address_map(self) -> dict[str, ipaddress.IPv4Network]:
        """
        Fetch all firewall address objects and return {name: IPv4Network}.
        FortiGate stores subnets as "IP NETMASK" (e.g. "192.168.1.0 255.255.255.0").
        """
        addr_map: dict[str, ipaddress.IPv4Network] = {}
        try:
            resp = self.get("/cmdb/firewall/address")
            for obj in resp.get("results", []):
                name   = obj.get("name", "")
                subnet = obj.get("subnet", "")
                if not subnet or "/" not in subnet and " " not in subnet:
                    continue
                try:
                    if " " in subnet:
                        ip, mask = subnet.split()
                        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    else:
                        net = ipaddress.IPv4Network(subnet, strict=False)
                    addr_map[name] = net
                except ValueError:
                    pass
        except Exception as e:
            log.warning(f"Address object fetch failed: {e}")
        return addr_map


# ---------------------------------------------------------------------------
# FortiAnalyzer API client
# ---------------------------------------------------------------------------

class FortiAnalyzerAPI:
    def __init__(self, cfg: dict):
        self.url     = f"https://{cfg['host']}:{cfg['port']}/jsonrpc"
        self.adom    = cfg["adom"]
        self.verify  = cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-Auth-Token": cfg["api_token"],
        })
        self._req_id = 1

    def _rpc(self, method: str, params: list) -> dict:
        payload = {
            "id":      self._req_id,
            "method":  method,
            "params":  params,
            "jsonrpc": "2.0",
        }
        self._req_id += 1
        r = self.session.post(self.url, json=payload,
                              verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_policy_log_counts(self, tag: str, hours: int) -> dict[str, int]:
        """
        Query traffic logs for the observation window and return
        {policyid_str: log_entry_count} for all policies seen in logs.
        """
        end_time   = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        try:
            resp = self._rpc("get", [{
                "url": f"/logview/adom/{self.adom}/logfiles/traffic",
                "apiver": 3,
                "filter":     f"comment like '%{tag}%'",
                "time-order": "desc",
                "limit":      10000,
                "start-time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end-time":   end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }])
            logs = resp.get("result", [{}])[0].get("data", [])
            counts: dict[str, int] = {}
            for entry in logs:
                pid = str(entry.get("policyid") or entry.get("policy_id") or "")
                if pid:
                    counts[pid] = counts.get(pid, 0) + 1
            return counts
        except Exception as e:
            log.warning(f"FortiAnalyzer log query failed: {e}")
            return {}


# ---------------------------------------------------------------------------
# CIDR resolution
# ---------------------------------------------------------------------------

def _name_to_cidr_fallback(name: str) -> Optional[ipaddress.IPv4Network]:
    """
    Parse a LAB address object name back to a CIDR without hitting the API.
    Handles LAB-NET-A-B-C-D_PL, LAB-SUB-..., LAB-HOST-A-B-C-D.
    Returns None for names that don't match the LAB naming scheme.
    """
    for prefix in ("LAB-NET-", "LAB-SUB-", "LAB-HOST-"):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            try:
                if "_" in rest:
                    ip_part, prefix_len = rest.rsplit("_", 1)
                    cidr = f"{ip_part.replace('-', '.')}/{prefix_len}"
                else:
                    cidr = f"{rest.replace('-', '.')}/32"
                return ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                return None
    return None


def resolve_cidr(
    name: str,
    addr_map: dict[str, ipaddress.IPv4Network],
) -> Optional[ipaddress.IPv4Network]:
    """
    Resolve an address object name to an IPv4Network.
    Primary: FortiGate address CMDB map.
    Fallback: LAB name-parsing heuristic.
    """
    if name in addr_map:
        return addr_map[name]
    return _name_to_cidr_fallback(name)


# ---------------------------------------------------------------------------
# Pass A — Behavioral detection (unused rules)
# ---------------------------------------------------------------------------

def run_behavioral_pass(
    fgt: FortiGateAPI,
    lab_policies: list[dict],
) -> dict:
    """
    Identify policies with zero hits using FortiGate monitor API only.

    GET /api/v2/monitor/firewall/policy returns hit_count, bytes, packets,
    last_used, and a 7-day daily breakdown per policy — no FAZ required.

    A policy is flagged "unused" if hit_count == 0.
    """
    console.print("\n[bold cyan]Pass A — Behavioral: FortiGate hit-count analysis")

    # Build policyid → policy map for LAB policies
    pid_to_policy = {
        str(p.get("policyid", "")): p for p in lab_policies
    }

    # Fetch all policy stats from FortiGate monitor endpoint
    hitcount_data = fgt.get_policy_hitcounts()
    if not hitcount_data:
        console.print(
            "[bold red]  WARNING: FortiGate monitor API returned no policy stats.\n"
            "  Hit counts will show as 0. Possible causes:\n"
            "    • Traffic phase (phase2) hasn't been run yet\n"
            "    • Monitor API endpoint unreachable or token lacks read access\n"
            "    • FortiGate takes a few minutes to update counters after traffic"
        )
    else:
        console.print(f"  Monitor API returned stats for [bold]{len(hitcount_data)}[/bold] policies")

    fgt_hits: dict[str, dict] = {}
    for entry in hitcount_data:
        pid = str(entry.get("policyid") or "")
        if pid:
            fgt_hits[pid] = entry

    # Classify each lab policy; try multiple FortiOS field name variants
    unused: list[dict] = []
    used:   list[dict] = []

    for pid, policy in pid_to_policy.items():
        stats = fgt_hits.get(pid, {})
        # FortiOS uses hit_count in some versions, hit-count in others
        hit_count = (
            stats.get("hit_count")
            or stats.get("hit-count")
            or stats.get("hitcount")
            or 0
        )
        bytes_ = stats.get("bytes") or stats.get("bytes-tx") or 0
        last_used = stats.get("last_used") or stats.get("last-used") or 0

        record = {
            "policyid":  pid,
            "name":      policy.get("name", ""),
            "hit_count": hit_count,
            "bytes":     bytes_,
            "last_used": last_used,
        }
        if hit_count == 0:
            unused.append(record)
        else:
            used.append(record)

    console.print(f"  Total lab policies : {len(lab_policies)}")
    console.print(f"  Used (hits > 0)    : [green]{len(used)}")
    console.print(f"  Unused (0 hits)    : [red]{len(unused)}")

    return {
        "unused":       unused,
        "used":         used,
        "sources_used": ["FortiGate monitor/firewall/policy"],
    }


# ---------------------------------------------------------------------------
# Pass B — Structural detection (CIDR analysis)
# ---------------------------------------------------------------------------

def run_structural_pass(
    lab_policies: list[dict],
    addr_map: dict[str, ipaddress.IPv4Network],
) -> dict:
    """
    Analyse the policy list (in FortiGate sequence order) to find:
      - Duplicate rules  : identical (src, dst, service, action)
      - Shadow rules     : earlier broad rule covers later narrow rule's full range (same service)
      - Subnet overlap   : earlier /24 src covers later /28-/32 src (same dst + service)
      - Collapsible svc  : same (src, dst) pair across multiple rules with different services
    """
    console.print("\n[bold cyan]Pass B — Structural: CIDR containment analysis")

    # Resolve CIDRs for each policy (first srcaddr / dstaddr entry only)
    resolved: list[dict] = []
    unresolved = 0
    for p in lab_policies:
        src_name = (p.get("srcaddr") or [{}])[0].get("name", "")
        dst_name = (p.get("dstaddr") or [{}])[0].get("name", "")
        svc_name = (p.get("service") or [{}])[0].get("name", "")
        src_net  = resolve_cidr(src_name, addr_map)
        dst_net  = resolve_cidr(dst_name, addr_map)
        if src_net is None or dst_net is None:
            unresolved += 1
        resolved.append({
            "policy":    p,
            "src_net":   src_net,
            "dst_net":   dst_net,
            "src_name":  src_name,
            "dst_name":  dst_name,
            "svc_name":  svc_name,
            "action":    p.get("action", "accept"),
        })

    if unresolved:
        console.print(f"  [yellow]Warning: {unresolved} policies had unresolvable address objects")

    # ── Duplicate detection ────────────────────────────────────────────────
    # Group by (src_net, dst_net, svc, action); groups with >1 member = duplicates.
    dup_buckets: dict[tuple, list[dict]] = defaultdict(list)
    for r in resolved:
        if r["src_net"] is None or r["dst_net"] is None:
            continue
        key = (str(r["src_net"]), str(r["dst_net"]), r["svc_name"], r["action"])
        dup_buckets[key].append(r["policy"])
    duplicate_groups = [g for g in dup_buckets.values() if len(g) > 1]

    # Flatten for quick lookup (all policyids involved in a duplicate group)
    duplicate_ids: set[str] = {
        str(p.get("policyid", ""))
        for group in duplicate_groups
        for p in group
    }

    # ── Shadow + subnet-overlap detection ─────────────────────────────────
    # O(n²) scan over pairs (i, j) where i comes before j in sequence.
    shadow_pairs:  list[tuple[dict, dict]] = []
    subnet_pairs:  list[tuple[dict, dict]] = []

    shadowed_ids:      set[str] = set()
    subnet_specific_ids: set[str] = set()

    for i, ri in enumerate(resolved):
        if ri["src_net"] is None or ri["dst_net"] is None:
            continue
        for rj in resolved[i + 1:]:
            if rj["src_net"] is None or rj["dst_net"] is None:
                continue

            src_contains = ri["src_net"].supernet_of(rj["src_net"])
            dst_contains = ri["dst_net"].supernet_of(rj["dst_net"])
            same_svc     = ri["svc_name"] == rj["svc_name"]
            src_strictly_broader = src_contains and ri["src_net"] != rj["src_net"]

            # Shadow: same service, ri's src+dst both contain rj's src+dst
            if same_svc and src_contains and dst_contains:
                pj_id = str(rj["policy"].get("policyid", ""))
                # Only flag as shadow if not already a pure duplicate
                if pj_id not in duplicate_ids:
                    shadow_pairs.append((ri["policy"], rj["policy"]))
                    shadowed_ids.add(pj_id)

            # Subnet overlap: ri's src strictly contains rj's src, same dst, any service
            # (dst must be the same network to distinguish from shadow)
            elif src_strictly_broader and (str(ri["dst_net"]) == str(rj["dst_net"])):
                pj_id = str(rj["policy"].get("policyid", ""))
                if pj_id not in duplicate_ids and pj_id not in shadowed_ids:
                    subnet_pairs.append((ri["policy"], rj["policy"]))
                    subnet_specific_ids.add(pj_id)

    # ── Collapsible service detection ──────────────────────────────────────
    # Group by (src_net, dst_net); groups with >1 different services = collapsible.
    svc_buckets: dict[tuple, list[dict]] = defaultdict(list)
    for r in resolved:
        if r["src_net"] is None or r["dst_net"] is None:
            continue
        key = (str(r["src_net"]), str(r["dst_net"]))
        svc_buckets[key].append(r["policy"])

    svc_groups = [
        g for g in svc_buckets.values()
        if len(g) > 1
        and len({(p.get("service") or [{}])[0].get("name", "") for p in g}) > 1
    ]

    console.print(f"  Policies analysed  : {len(resolved)}")
    console.print(f"  Duplicate groups   : [yellow]{len(duplicate_groups)}")
    console.print(f"  Shadow pairs       : [yellow]{len(shadow_pairs)}")
    console.print(f"  Subnet-overlap pairs: [yellow]{len(subnet_pairs)}")
    console.print(f"  Collapsible svc groups: [yellow]{len(svc_groups)}")

    return {
        "duplicate_groups": duplicate_groups,
        "shadow_pairs":     shadow_pairs,
        "subnet_pairs":     subnet_pairs,
        "svc_groups":       svc_groups,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(
    lab_policies: list[dict],
    structural: dict,
    behavioral: Optional[dict] = None,
):
    total = len(lab_policies)

    console.rule("[bold cyan]Phase 3 — Traditional: CIDR + Log-based Detection")
    console.print(
        f"Total [bold]{TAG}[/bold] policies fetched from FortiGate: "
        f"[bold]{total}[/bold]"
    )
    if behavioral is not None:
        src_note = ", ".join(behavioral["sources_used"])
        console.print(f"Behavioral sources: {src_note}")
    else:
        console.print("[dim]Behavioral pass skipped (--skip-unused)[/dim]")
    console.print()

    # ── Summary table ─────────────────────────────────────────────────────
    n_dup_policies = sum(len(g) for g in structural["duplicate_groups"])
    n_shadow       = len(structural["shadow_pairs"])
    n_subnet       = len(structural["subnet_pairs"])
    n_svc          = sum(len(g) for g in structural["svc_groups"])

    summary = Table(title="Detected Issue Summary", show_lines=True)
    summary.add_column("Category",         style="cyan",   min_width=26)
    summary.add_column("Count",            style="yellow", justify="right")
    summary.add_column("Detection Method", style="white",  min_width=56)

    if behavioral is not None:
        summary.add_row(
            "Unused (zero hits)",
            str(len(behavioral["unused"])),
            "hit_count == 0 from FortiGate monitor API"
            + (" + FAZ log counts" if len(behavioral["sources_used"]) > 1 else ""),
        )
    summary.add_row(
        "Shadow (broad — catches traffic)",
        str(n_shadow),
        "Earlier rule: src_i ⊇ src_j AND dst_i ⊇ dst_j, same service",
    )
    summary.add_row(
        "Shadow (specific — unreachable)",
        str(n_shadow),
        "Later rule fully covered by the earlier broad rule above",
    )
    summary.add_row(
        "Duplicate policies",
        str(n_dup_policies),
        "Exact (src_cidr, dst_cidr, service, action) tuple match",
    )
    summary.add_row(
        "Subnet overlap (broad /24)",
        str(n_subnet),
        "Earlier /24 src_cidr strictly contains the specific rule's src below it",
    )
    summary.add_row(
        "Subnet overlap (specific /28-/32)",
        str(n_subnet),
        "Later rule's src_cidr fully contained by the broader rule above",
    )
    summary.add_row(
        "Collapsible service rules",
        str(n_svc),
        "Same (src_cidr, dst_cidr) pair, different services — could be one rule",
    )

    console.print(summary)

    # ── Shadow pairs ──────────────────────────────────────────────────────
    if structural["shadow_pairs"]:
        console.print(
            f"\n[bold yellow]Shadow Pairs ({len(structural['shadow_pairs'])} pairs)[/bold yellow]"
        )
        t = Table(show_lines=True)
        t.add_column("Broad rule (catches traffic)", style="green")
        t.add_column("Broad src",  style="cyan")
        t.add_column("Broad dst",  style="cyan")
        t.add_column("Shadowed rule (unreachable)", style="red")
        t.add_column("Narrow src", style="cyan")
        t.add_column("Service",    style="white")
        for broad, specific in structural["shadow_pairs"]:
            b_src = (broad.get("srcaddr")    or [{}])[0].get("name", "?")
            b_dst = (broad.get("dstaddr")    or [{}])[0].get("name", "?")
            s_src = (specific.get("srcaddr") or [{}])[0].get("name", "?")
            svc   = (broad.get("service")    or [{}])[0].get("name", "?")
            t.add_row(broad["name"], b_src, b_dst, specific["name"], s_src, svc)
        console.print(t)

    # ── Duplicate groups ──────────────────────────────────────────────────
    if structural["duplicate_groups"]:
        console.print(
            f"\n[bold yellow]Duplicate Groups ({len(structural['duplicate_groups'])} groups)[/bold yellow]"
        )
        t = Table(show_lines=True)
        t.add_column("Rule name", style="white")
        t.add_column("Src",       style="cyan")
        t.add_column("Dst",       style="cyan")
        t.add_column("Service",   style="cyan")
        for group in structural["duplicate_groups"]:
            for p in group:
                src = (p.get("srcaddr") or [{}])[0].get("name", "?")
                dst = (p.get("dstaddr") or [{}])[0].get("name", "?")
                svc = (p.get("service") or [{}])[0].get("name", "?")
                t.add_row(p["name"], src, dst, svc)
            t.add_section()
        console.print(t)

    # ── Subnet overlap pairs ──────────────────────────────────────────────
    if structural["subnet_pairs"]:
        console.print(
            f"\n[bold yellow]Subnet Overlap Pairs ({len(structural['subnet_pairs'])} pairs)[/bold yellow]"
        )
        t = Table(show_lines=True)
        t.add_column("Broad /24 rule",       style="green")
        t.add_column("Broad src",            style="cyan")
        t.add_column("Specific /28-32 rule", style="red")
        t.add_column("Specific src",         style="cyan")
        t.add_column("Service",              style="cyan")
        for broad, specific in structural["subnet_pairs"]:
            b_src = (broad.get("srcaddr")    or [{}])[0].get("name", "?")
            s_src = (specific.get("srcaddr") or [{}])[0].get("name", "?")
            svc   = (broad.get("service")    or [{}])[0].get("name", "?")
            t.add_row(broad["name"], b_src, specific["name"], s_src, svc)
        console.print(t)

    # ── Collapsible service groups ────────────────────────────────────────
    if structural["svc_groups"]:
        console.print(
            f"\n[bold yellow]Collapsible Service Groups ({len(structural['svc_groups'])} clusters)[/bold yellow]"
        )
        t = Table(show_lines=True)
        t.add_column("Rule name", style="white")
        t.add_column("Src",       style="cyan")
        t.add_column("Dst",       style="cyan")
        t.add_column("Service",   style="cyan")
        for group in structural["svc_groups"]:
            for p in group:
                src = (p.get("srcaddr") or [{}])[0].get("name", "?")
                dst = (p.get("dstaddr") or [{}])[0].get("name", "?")
                svc = (p.get("service") or [{}])[0].get("name", "?")
                t.add_row(p["name"], src, dst, svc)
            t.add_section()
        console.print(t)

    # ── Hit count table (all lab policies from FortiGate) ────────────────
    if behavioral is not None:
        all_policies = behavioral["used"] + behavioral["unused"]
        all_policies.sort(key=lambda p: int(p["hit_count"]), reverse=True)
        console.print(
            f"\n[bold yellow]FortiGate Hit Counts — All Lab Policies "
            f"({len(all_policies)} total, source: monitor/firewall/policy)[/bold yellow]"
        )
        t = Table(show_lines=True)
        t.add_column("Policy ID", style="white",  justify="right")
        t.add_column("Name",      style="white")
        t.add_column("Hit count", style="cyan",   justify="right")
        t.add_column("Bytes",     style="cyan",   justify="right")
        t.add_column("Status",    style="yellow")
        for p in all_policies:
            status = "[green]used" if int(p["hit_count"]) > 0 else "[red]unused"
            t.add_row(
                str(p["policyid"]),
                p["name"],
                str(p["hit_count"]),
                str(p["bytes"]),
                status,
            )
        console.print(t)

    # ── Totals ────────────────────────────────────────────────────────────
    unique_flagged: set[str] = set()
    if behavioral is not None:
        for p in behavioral["unused"]:
            unique_flagged.add(str(p["policyid"]))
    for broad, specific in structural["shadow_pairs"]:
        unique_flagged.add(str(broad.get("policyid", "")))
        unique_flagged.add(str(specific.get("policyid", "")))
    for group in structural["duplicate_groups"]:
        for p in group:
            unique_flagged.add(str(p.get("policyid", "")))
    for broad, specific in structural["subnet_pairs"]:
        unique_flagged.add(str(broad.get("policyid", "")))
        unique_flagged.add(str(specific.get("policyid", "")))
    for group in structural["svc_groups"]:
        for p in group:
            unique_flagged.add(str(p.get("policyid", "")))

    n_flagged = len(unique_flagged)
    console.print(
        f"\n[bold]Total:[/bold] {total} policies — "
        f"[red]{n_flagged} flagged with at least one issue[/red], "
        f"[green]{total - n_flagged} appear clean[/green]"
    )
    console.print(
        "\n[dim]Compare these counts against phase3_zero.py to measure detection accuracy.[/dim]"
    )


# ---------------------------------------------------------------------------
# JSON output builder
# ---------------------------------------------------------------------------

def _policy_detail(p: dict) -> dict:
    """Extract the fields Claude Code needs to act on a policy without extra API calls."""
    return {
        "policyid": p.get("policyid"),
        "name":     p.get("name"),
        "srcaddr":  [a["name"] for a in p.get("srcaddr", [])],
        "dstaddr":  [a["name"] for a in p.get("dstaddr", [])],
        "service":  [s["name"] for s in p.get("service",  [])],
        "action":   p.get("action", "accept"),
        "seq":      p.get("policyid"),  # FortiGate sequence ≈ policyid in CMDB order
    }


def build_json_report(structural: dict, behavioral: Optional[dict] = None) -> dict:
    # Collect every flagged policy into a name-keyed index so Claude Code
    # can look up policyid / srcaddr / dstaddr / service without an extra API call.
    flagged: dict[str, dict] = {}

    def _index(*policies):
        for p in policies:
            flagged[p["name"]] = _policy_detail(p)

    for broad, specific in structural["shadow_pairs"]:
        _index(broad, specific)
    for group in structural["duplicate_groups"]:
        for p in group:
            _index(p)
    for broad, specific in structural["subnet_pairs"]:
        _index(broad, specific)
    for group in structural["svc_groups"]:
        for p in group:
            _index(p)

    report: dict = {
        "source":  "phase3_traditional",
        "sources_used": behavioral["sources_used"] if behavioral else [],
        "counts": {
            "unused":                len(behavioral["unused"]) if behavioral else None,
            "shadow_pairs":          len(structural["shadow_pairs"]),
            "duplicate_groups":      len(structural["duplicate_groups"]),
            "duplicate_policies":    sum(len(g) for g in structural["duplicate_groups"]),
            "subnet_overlap_pairs":  len(structural["subnet_pairs"]),
            "collapsible_svc_groups": len(structural["svc_groups"]),
        },
        # Enriched index — every flagged policy with full details
        "flagged_policies": flagged,
        "unused_policies": [
            {"policyid":  p["policyid"], "name": p["name"],
             "hit_count": p["hit_count"], "bytes": p["bytes"],
             "last_used": p["last_used"]}
            for p in (behavioral["unused"] if behavioral else [])
        ],
        "shadow_pairs": [
            {"broad": b["name"], "shadowed": s["name"]}
            for b, s in structural["shadow_pairs"]
        ],
        "duplicate_groups": [
            [p["name"] for p in g] for g in structural["duplicate_groups"]
        ],
        "subnet_overlap_pairs": [
            {"broad": b["name"], "specific": s["name"]}
            for b, s in structural["subnet_pairs"]
        ],
        "collapsible_svc_groups": [
            [p["name"] for p in g] for g in structural["svc_groups"]
        ],
    }
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--config", default="config.yaml",
              help="Path to config.yaml", show_default=True)
@click.option("--output", default=None,
              help="Optional path to write JSON report")
@click.option("--skip-unused", is_flag=True, default=False,
              help="Skip behavioral pass (hit-count + FAZ). "
                   "Runs structural CIDR analysis only. "
                   "No traffic or FortiAnalyzer required.")
def main(config, output, skip_unused):
    """
    Traditional detection: query FortiGate (+ optionally FortiAnalyzer) and use
    CIDR math to find shadow, duplicate, subnet-overlap, and collapsible-service rules.

    Use --skip-unused to run structural analysis only (no traffic data needed).
    Compare output against phase3_zero.py for accuracy scoring.
    """
    with open(config) as f:
        cfg = yaml.safe_load(f)

    fgt = FortiGateAPI(cfg["fortigate"])

    # Fetch policies and address map from FortiGate
    console.print("\n[cyan]Fetching policies from FortiGate...")
    lab_policies = fgt.get_all_lab_policies()
    if not lab_policies:
        console.print(f"[bold red]No {TAG} policies found on FortiGate. Run phase1 first.")
        sys.exit(1)
    console.print(f"  Found {len(lab_policies)} {TAG} policies")

    console.print("[cyan]Fetching address objects from FortiGate...")
    addr_map = fgt.get_address_map()
    console.print(f"  Resolved {len(addr_map)} address objects")

    # Pass A — Behavioral (optional)
    behavioral: Optional[dict] = None
    if not skip_unused:
        behavioral = run_behavioral_pass(fgt, lab_policies)

    # Pass B — Structural (always runs)
    structural = run_structural_pass(lab_policies, addr_map)

    # Print combined report
    print_report(lab_policies, structural, behavioral)

    # Optional JSON output
    if output:
        report = build_json_report(structural, behavioral)
        Path(output).write_text(json.dumps(report, indent=2))
        console.print(f"\n[green]JSON report saved: {output}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
