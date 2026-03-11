"""
Phase 3 — Unused Rule Detection & AI-based Optimization

Three parallel analysis paths:
  A. FortiGate native hit-count API + FortiAI policy optimization endpoint
  B. FortiAnalyzer log query — policies with zero log entries in window
  C. OpenAI (gpt-4o) + Anthropic (claude-sonnet) structured optimization prompts

Outputs:
  - analysis_report.json  : full structured results
  - fortigate_recommendations.txt
  - openai_recommendations.txt
  - anthropic_recommendations.txt
  - comparison_diff.txt   : side-by-side of AI model outputs
"""

import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

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
# FortiGate API Client (reused pattern from phase1)
# ---------------------------------------------------------------------------

class FortiGateAPI:
    def __init__(self, cfg: dict):
        self.base  = f"https://{cfg['host']}:{cfg['port']}/api/v2"
        self.token = cfg["api_token"]
        self.vdom  = cfg["vdom"]
        self.verify= cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _url(self, path: str, monitor: bool = False) -> str:
        base = self.base
        sep = "?" if "?" not in path else "&"
        return f"{base}{path}{sep}vdom={self.vdom}"

    def get(self, path: str) -> dict:
        r = self.session.get(self._url(path), verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, data: dict) -> dict:
        r = self.session.post(self._url(path), json=data, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_policy_hitcounts(self) -> list[dict]:
        """
        GET /api/v2/monitor/firewall/policy/
        Returns per-policy hit counts from FortiOS monitor API.
        """
        try:
            resp = self.get("/monitor/firewall/policy/")
            return resp.get("results", [])
        except Exception as e:
            log.error(f"Failed to get hit counts: {e}")
            return []

    def get_all_lab_policies(self) -> list[dict]:
        """Return all lab policies from config API."""
        try:
            resp = self.get("/cmdb/firewall/policy")
            return [
                p for p in resp.get("results", [])
                if TAG in p.get("comments", "")
            ]
        except Exception as e:
            log.error(f"Failed to fetch policies: {e}")
            return []

    def get_fortiai_recommendations(self) -> dict:
        """
        Call FortiAI policy analysis endpoint (FortiOS 7.4+).
        Endpoint: POST /api/v2/monitor/fortiai/policy-analysis
        Returns AI-generated optimization suggestions from FortiOS.
        """
        try:
            resp = self.post("/monitor/fortiai/policy-analysis", {
                "vdom": self.vdom,
                "scope": "policy",
            })
            return resp
        except Exception as e:
            log.warning(f"FortiAI endpoint not available or returned error: {e}")
            return {"error": str(e), "available": False}


# ---------------------------------------------------------------------------
# FortiAnalyzer API Client
# ---------------------------------------------------------------------------

class FortiAnalyzerAPI:
    """
    FortiAnalyzer JSON-RPC API (port 443 /jsonrpc).
    Authentication via API token passed as session header.
    """

    def __init__(self, cfg: dict):
        self.host    = cfg["host"]
        self.port    = cfg["port"]
        self.token   = cfg["api_token"]
        self.adom    = cfg["adom"]
        self.verify  = cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.url     = f"https://{self.host}:{self.port}/jsonrpc"
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-Auth-Token": self.token,
        })
        self._req_id = 1

    def _rpc(self, method: str, params: list) -> dict:
        payload = {
            "id": self._req_id,
            "method": method,
            "params": params,
            "jsonrpc": "2.0",
        }
        self._req_id += 1
        r = self.session.post(self.url, json=payload,
                              verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def query_logs_by_tag(
        self,
        tag: str,
        hours: int = 24,
        device: str = "FortiGate",
    ) -> list[dict]:
        """
        Query traffic logs filtered by comment tag within the last N hours.
        Returns log entries with policy IDs.
        """
        end_time   = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        try:
            resp = self._rpc("get", [{
                "url": f"/logview/adom/{self.adom}/logfiles/traffic",
                "apiver": 3,
                "filter": f"comment like '%{tag}%'",
                "time-order": "desc",
                "limit": 10000,
                "start-time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end-time":   end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }])
            return resp.get("result", [{}])[0].get("data", [])
        except Exception as e:
            log.error(f"FortiAnalyzer log query failed: {e}")
            return []

    def get_policy_usage_report(self, tag: str, hours: int) -> dict:
        """
        Returns {policy_id: hit_count} from FortiAnalyzer logs.
        """
        logs = self.query_logs_by_tag(tag, hours)
        usage: dict[str, int] = {}
        for entry in logs:
            pid = str(entry.get("policyid", entry.get("policy_id", "")))
            if pid:
                usage[pid] = usage.get(pid, 0) + 1
        return usage


# ---------------------------------------------------------------------------
# Path A — FortiGate Native Analysis
# ---------------------------------------------------------------------------

def analyze_fortigate_native(fgt: FortiGateAPI, observation_hours: int) -> dict:
    """
    Query FortiGate hit counts for all lab policies.
    Identify zero-hit policies as unused candidates.
    """
    console.print("\n[cyan]Path A: FortiGate native hit-count analysis...")

    lab_policies   = fgt.get_all_lab_policies()
    hitcount_data  = fgt.get_policy_hitcounts()

    # Build lookup: policy_id -> hit_count
    hitcount_map: dict[int, int] = {}
    for entry in hitcount_data:
        pid = entry.get("policyid", entry.get("id"))
        if pid is not None:
            hitcount_map[int(pid)] = entry.get("hit_count", entry.get("bytes", 0))

    unused    = []
    used      = []
    for p in lab_policies:
        pid    = p.get("policyid")
        hits   = hitcount_map.get(int(pid), 0) if pid else 0
        record = {
            "policyid": pid,
            "name":     p.get("name"),
            "comment":  p.get("comments", ""),
            "hits":     hits,
        }
        if hits == 0:
            unused.append(record)
        else:
            used.append(record)

    result = {
        "source":         "fortigate_native",
        "total_lab":      len(lab_policies),
        "used_count":     len(used),
        "unused_count":   len(unused),
        "unused_ratio":   len(unused) / max(len(lab_policies), 1),
        "unused_policies": unused,
        "used_policies":   used,
    }

    console.print(f"  Lab policies    : {result['total_lab']}")
    console.print(f"  Used (hits > 0) : {result['used_count']}")
    console.print(f"  [red]Unused (0 hits) : {result['unused_count']} "
                  f"({result['unused_ratio']*100:.1f}%)")

    # FortiAI recommendations
    console.print("\n[cyan]  Querying FortiAI policy optimizer...")
    fortiai_resp = fgt.get_fortiai_recommendations()
    result["fortiai"] = fortiai_resp
    if fortiai_resp.get("available") is False:
        console.print(f"  [yellow]FortiAI: {fortiai_resp.get('error', 'unavailable')}")
    else:
        console.print(f"  [green]FortiAI response received ({len(str(fortiai_resp))} bytes)")

    return result


# ---------------------------------------------------------------------------
# Path B — FortiAnalyzer Log Analysis
# ---------------------------------------------------------------------------

def analyze_fortianalyzer(faz: FortiAnalyzerAPI, lab_policies: list[dict],
                           observation_hours: int) -> dict:
    """
    Cross-reference FortiAnalyzer log entries against lab policy IDs.
    Policies absent from logs in the observation window = unused.
    """
    console.print("\n[cyan]Path B: FortiAnalyzer log analysis...")

    usage = faz.get_policy_usage_report(TAG, observation_hours)
    console.print(f"  Distinct policy IDs in logs: {len(usage)}")

    all_pids = {str(p.get("policyid")): p.get("name") for p in lab_policies}
    unused_faz   = []
    used_faz     = []

    for pid, name in all_pids.items():
        hits = usage.get(pid, 0)
        record = {"policyid": pid, "name": name, "log_hits": hits}
        if hits == 0:
            unused_faz.append(record)
        else:
            used_faz.append(record)

    result = {
        "source":          "fortianalyzer",
        "observation_hours": observation_hours,
        "total_lab":       len(all_pids),
        "used_count":      len(used_faz),
        "unused_count":    len(unused_faz),
        "unused_ratio":    len(unused_faz) / max(len(all_pids), 1),
        "unused_policies": unused_faz,
        "used_policies":   used_faz,
    }

    console.print(f"  Lab policies    : {result['total_lab']}")
    console.print(f"  Used in logs    : {result['used_count']}")
    console.print(f"  [red]Unused in logs  : {result['unused_count']} "
                  f"({result['unused_ratio']*100:.1f}%)")

    return result


# ---------------------------------------------------------------------------
# Path C — AI-based Optimization
# ---------------------------------------------------------------------------

OPTIMIZATION_PROMPT = """
You are a senior network security engineer specializing in firewall policy optimization.

You are given:
1. A set of firewall policies (JSON) generated for a lab scenario
2. Usage statistics showing which policies had zero hits in the observation window

Your task:
- Identify all unused policies (zero hits) and explain WHY they are likely unused
- Identify shadow rules (policies that can never be reached due to a preceding broader rule)
- Identify duplicate rules (identical or near-identical src/dst/service/action)
- Identify rules that can be collapsed (same src/dst, multiple services → one rule with service group)
- Produce a recommended consolidated rule set (JSON format)
- Provide a summary table: original count → recommended count, with breakdown

Format your response as:

## UNUSED POLICIES
[list with policyid, name, reason]

## SHADOW RULES
[list with policyid, name, shadowed-by]

## DUPLICATE RULES
[list of duplicate groups]

## COLLAPSIBLE RULES
[list of collapsible groups with recommended merged rule]

## RECOMMENDED CONSOLIDATED RULESET
[JSON array of recommended policies]

## SUMMARY
[table: metric | before | after | reduction%]

Be specific. Reference policy names. Do not generalize.
"""


def _build_ai_payload(lab_policies: list[dict], unused_policies: list[dict]) -> str:
    """Build the prompt payload for AI models."""
    # Trim policies to avoid token overflow — send names/src/dst/svc/comment only
    trimmed = []
    for p in lab_policies[:300]:  # cap at 300 for context window safety
        trimmed.append({
            "policyid": p.get("policyid"),
            "name":     p.get("name"),
            "srcaddr":  [x.get("name") for x in p.get("srcaddr", [])],
            "dstaddr":  [x.get("name") for x in p.get("dstaddr", [])],
            "service":  [x.get("name") for x in p.get("service", [])],
            "action":   p.get("action"),
            "comments": p.get("comments", ""),
        })

    unused_ids = [u.get("policyid") or u.get("name") for u in unused_policies]

    payload = (
        f"TOTAL POLICIES: {len(lab_policies)}\n"
        f"UNUSED POLICY IDs (zero hits): {json.dumps(unused_ids)}\n\n"
        f"POLICY DEFINITIONS (first 300):\n{json.dumps(trimmed, indent=2)}"
    )
    return payload


def analyze_openai(cfg: dict, lab_policies: list[dict], unused_policies: list[dict]) -> str:
    """Send policy data to OpenAI gpt-4o for optimization recommendations."""
    console.print("\n[cyan]Path C1: OpenAI analysis...")
    try:
        import openai
        client = openai.OpenAI(api_key=cfg["ai"]["openai_api_key"])
        payload = _build_ai_payload(lab_policies, unused_policies)

        response = client.chat.completions.create(
            model=cfg["ai"]["openai_model"],
            max_tokens=cfg["ai"]["max_tokens"],
            messages=[
                {"role": "system", "content": OPTIMIZATION_PROMPT},
                {"role": "user",   "content": payload},
            ],
        )
        text = response.choices[0].message.content
        console.print(f"  [green]OpenAI response: {len(text)} chars")
        return text
    except Exception as e:
        msg = f"OpenAI analysis failed: {e}"
        log.error(msg)
        console.print(f"  [red]{msg}")
        return msg


def analyze_anthropic(cfg: dict, lab_policies: list[dict], unused_policies: list[dict]) -> str:
    """Send policy data to Anthropic claude-sonnet for optimization recommendations."""
    console.print("\n[cyan]Path C2: Anthropic analysis...")
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=cfg["ai"]["anthropic_api_key"])
        payload = _build_ai_payload(lab_policies, unused_policies)

        response = client.messages.create(
            model=cfg["ai"]["anthropic_model"],
            max_tokens=cfg["ai"]["max_tokens"],
            system=OPTIMIZATION_PROMPT,
            messages=[
                {"role": "user", "content": payload},
            ],
        )
        text = response.content[0].text
        console.print(f"  [green]Anthropic response: {len(text)} chars")
        return text
    except Exception as e:
        msg = f"Anthropic analysis failed: {e}"
        log.error(msg)
        console.print(f"  [red]{msg}")
        return msg


def generate_diff_report(openai_text: str, anthropic_text: str) -> str:
    """Produce a side-by-side comparison summary of both AI outputs."""
    lines = [
        "=" * 80,
        "AI MODEL COMPARISON REPORT",
        "=" * 80,
        "",
        "MODEL A: OpenAI GPT-4o",
        "-" * 40,
        openai_text,
        "",
        "=" * 80,
        "",
        "MODEL B: Anthropic Claude",
        "-" * 40,
        anthropic_text,
        "",
        "=" * 80,
        "NOTE: Both models received identical input. Compare recommendations above.",
        "      Policies flagged by BOTH models as unused are high-confidence candidates.",
        "      Discrepancies indicate borderline cases requiring manual review.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Summary Table
# ---------------------------------------------------------------------------

def print_summary_table(fgt_result: dict, faz_result: dict):
    t = Table(title="Unused Rule Analysis — Summary", show_lines=True)
    t.add_column("Source",            style="cyan")
    t.add_column("Total Lab Policies",style="white")
    t.add_column("Used",              style="green")
    t.add_column("Unused",            style="red")
    t.add_column("Unused %",          style="yellow")

    for res in [fgt_result, faz_result]:
        t.add_row(
            res["source"],
            str(res["total_lab"]),
            str(res["used_count"]),
            str(res["unused_count"]),
            f"{res['unused_ratio']*100:.1f}%",
        )
    console.print(t)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(config_path: str):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    output_dir = Path(cfg["lab"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    obs_hours  = cfg["lab"]["observation_window_hours"]

    console.rule("[bold cyan]Phase 3 — Unused Rule Analysis")

    fgt = FortiGateAPI(cfg["fortigate"])
    faz = FortiAnalyzerAPI(cfg["fortianalyzer"])

    # Load generated rules from disk for AI context
    rules_file = output_dir / cfg["lab"]["rules_backup_file"]
    lab_policies_local = []
    if rules_file.exists():
        with open(rules_file) as f:
            data = json.load(f)
        lab_policies_local = data.get("policies", [])

    # Path A: FortiGate native
    fgt_result = analyze_fortigate_native(fgt, obs_hours)

    # Path B: FortiAnalyzer
    faz_result = analyze_fortianalyzer(
        faz,
        fgt.get_all_lab_policies(),
        obs_hours
    )

    # Merge unused lists for AI context (union of both sources)
    unused_union = {
        p.get("policyid") or p.get("name"): p
        for p in (fgt_result["unused_policies"] + faz_result["unused_policies"])
    }
    unused_merged = list(unused_union.values())

    # Path C: AI analysis
    openai_text    = analyze_openai(cfg, lab_policies_local, unused_merged)
    anthropic_text = analyze_anthropic(cfg, lab_policies_local, unused_merged)
    diff_report    = generate_diff_report(openai_text, anthropic_text)

    # Summary table
    print_summary_table(fgt_result, faz_result)

    # Write outputs
    report = {
        "generated_at":     datetime.utcnow().isoformat(),
        "observation_hours": obs_hours,
        "fortigate_native": fgt_result,
        "fortianalyzer":    faz_result,
        "unused_union_count": len(unused_merged),
        "fortiai":          fgt_result.get("fortiai", {}),
    }

    report_file = output_dir / cfg["lab"]["analysis_report_file"]
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[green]Analysis report saved: {report_file}")

    for fname, content in [
        ("openai_recommendations.txt",    openai_text),
        ("anthropic_recommendations.txt", anthropic_text),
        ("comparison_diff.txt",           diff_report),
    ]:
        path = output_dir / fname
        path.write_text(content)
        console.print(f"[green]Saved: {path}")

    console.print(f"\n[bold green]Phase 3 complete.")
    return report


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    config = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    run(config)
