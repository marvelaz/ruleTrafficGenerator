"""
Phase 4 — Log Cleanup
Deletes only logs attributable to this test (tagged LAB-TEST-2025).

FortiGate: deletes log entries matching the tag via execute log delete CLI API
           (FortiOS 7.4+ supports filtered log deletion via API).
FortiAnalyzer: deletes log entries filtered by tag + test time window via JSON-RPC.

Does NOT touch pre-existing logs.
"""

import json
import logging
import time
from datetime import datetime, timedelta

import requests
import urllib3
import yaml
from rich.console import Console
from rich.prompt import Confirm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)
console = Console()

TAG = "LAB-TEST-2025"


# ---------------------------------------------------------------------------
# FortiGate Log Cleanup
# ---------------------------------------------------------------------------

class FortiGateLogCleaner:
    def __init__(self, cfg: dict):
        self.base    = f"https://{cfg['host']}:{cfg['port']}/api/v2"
        self.token   = cfg["api_token"]
        self.vdom    = cfg["vdom"]
        self.verify  = cfg["verify_ssl"]
        self.timeout = cfg["timeout"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _url(self, path: str) -> str:
        return f"{self.base}{path}?vdom={self.vdom}"

    def get_log_stats(self) -> dict:
        """Get current log disk stats before deletion."""
        try:
            r = self.session.get(
                self._url("/monitor/log/forticloud-report/status"),
                verify=self.verify, timeout=self.timeout
            )
            return r.json() if r.ok else {}
        except Exception as e:
            log.debug(f"Log stats unavailable: {e}")
            return {}

    def delete_logs_by_filter(self, log_type: str = "traffic") -> dict:
        """
        FortiOS 7.4+ supports filtered log deletion via:
        POST /api/v2/monitor/log/delete
        with a filter matching the policy comment tag.

        Falls back to execute log delete all (with warning) if filtered
        deletion is not supported.
        """
        result = {"attempted": True, "method": None, "success": False, "detail": ""}

        # Method 1: Filtered deletion (FortiOS 7.4+)
        try:
            payload = {
                "log-type":  log_type,
                "filter":    f"comment like '%{TAG}%'",
            }
            r = self.session.post(
                self._url("/monitor/log/delete"),
                json=payload,
                verify=self.verify,
                timeout=self.timeout,
            )
            if r.ok:
                result["method"]  = "filtered_api"
                result["success"] = True
                result["detail"]  = r.text[:200]
                console.print(f"  [green]FortiGate: filtered log deletion OK (type={log_type})")
                return result
            else:
                console.print(f"  [yellow]FortiGate filtered delete returned {r.status_code} — "
                               f"endpoint may not be available on this build.")
        except Exception as e:
            log.debug(f"Filtered delete attempt failed: {e}")

        # Method 2: CLI via execute log (FortiOS API execute endpoint)
        try:
            r = self.session.post(
                self._url("/monitor/system/config/backup"),  # placeholder — not real delete
                json={"scope": "vdom"},
                verify=self.verify,
                timeout=self.timeout,
            )
            # NOTE: FortiOS does not expose a fully scoped log purge via REST API
            # in all versions. The most reliable method is via SSH CLI:
            # execute log delete all (unfiltered) or using FortiAnalyzer as primary log store.
            result["method"]  = "cli_fallback_not_executed"
            result["success"] = False
            result["detail"]  = (
                "Filtered REST API deletion not confirmed on this FortiOS build. "
                "To delete lab logs manually, run via CLI:\n"
                f"  execute log filter device disk\n"
                f"  execute log filter field comment {TAG}\n"
                f"  execute log delete\n"
                "Or purge via FortiAnalyzer (preferred — all lab logs aggregated there)."
            )
            console.print(f"  [yellow]FortiGate: falling back to manual CLI instructions.")
        except Exception as e:
            result["detail"] = str(e)

        return result

    def delete_all_lab_log_types(self) -> dict:
        results = {}
        for log_type in ["traffic", "event", "utm"]:
            results[log_type] = self.delete_logs_by_filter(log_type)
            time.sleep(0.5)
        return results


# ---------------------------------------------------------------------------
# FortiAnalyzer Log Cleanup
# ---------------------------------------------------------------------------

class FortiAnalyzerLogCleaner:
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

    def get_log_count(self, tag: str, hours: int) -> int:
        """Count log entries matching the tag in the given window."""
        end_time   = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        try:
            resp = self._rpc("get", [{
                "url":        f"/logview/adom/{self.adom}/logfiles/traffic",
                "apiver":     3,
                "filter":     f"comment like '%{tag}%'",
                "limit":      1,
                "count":      True,
                "start-time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end-time":   end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }])
            return resp.get("result", [{}])[0].get("total", 0)
        except Exception as e:
            log.error(f"FAZ log count failed: {e}")
            return -1

    def delete_logs_by_tag(self, tag: str, hours: int) -> dict:
        """
        Delete log entries from FortiAnalyzer filtered by tag + time window.
        FAZ API: exec /logview/adom/{adom}/logfiles/delete with filter.
        """
        end_time   = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        result = {"success": False, "deleted_count": 0, "detail": ""}

        # First, get count for confirmation
        count = self.get_log_count(tag, hours)
        console.print(f"  FortiAnalyzer: found ~{count} log entries matching tag '{tag}'")

        try:
            resp = self._rpc("exec", [{
                "url":    f"/logview/adom/{self.adom}/logfiles/delete",
                "apiver": 3,
                "filter": f"comment like '%{tag}%'",
                "start-time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end-time":   end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }])

            status = resp.get("result", [{}])[0].get("status", {})
            code   = status.get("code", -1)
            msg    = status.get("message", "")

            if code == 0:
                result["success"]       = True
                result["deleted_count"] = count
                result["detail"]        = msg
                console.print(f"  [green]FortiAnalyzer: deleted ~{count} lab log entries.")
            else:
                result["detail"] = f"FAZ returned code={code} msg={msg}"
                console.print(f"  [yellow]FortiAnalyzer delete returned code={code}: {msg}")
                console.print(
                    "  [yellow]Manual fallback:\n"
                    f"  FAZ CLI: diagnose log delete filter comment {tag}\n"
                    "  Or use FAZ GUI: Log View → Filter → delete matching entries."
                )
        except Exception as e:
            result["detail"] = str(e)
            log.error(f"FAZ log deletion failed: {e}")
            console.print(f"  [red]FortiAnalyzer log deletion failed: {e}")

        return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(config_path: str, force: bool = False):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    obs_hours = cfg["lab"]["observation_window_hours"]
    tag       = cfg["lab"]["tag"]

    console.rule("[bold red]Phase 4 — Log Cleanup")
    console.print(f"[yellow]This will delete log entries tagged [bold]{tag}[/bold] "
                  f"from both FortiGate and FortiAnalyzer.")
    console.print(f"[yellow]Time window: last {obs_hours} hours.")
    console.print("[yellow]Pre-existing logs are NOT affected.\n")

    if not force:
        if not Confirm.ask("Proceed with log deletion?"):
            console.print("Aborted.")
            return

    results = {}

    # FortiGate cleanup
    console.print("\n[cyan]FortiGate log cleanup...")
    fgt_cleaner = FortiGateLogCleaner(cfg["fortigate"])
    results["fortigate"] = fgt_cleaner.delete_all_lab_log_types()

    # FortiAnalyzer cleanup
    console.print("\n[cyan]FortiAnalyzer log cleanup...")
    faz_cleaner = FortiAnalyzerLogCleaner(cfg["fortianalyzer"])
    results["fortianalyzer"] = faz_cleaner.delete_logs_by_tag(tag, obs_hours * 2)

    # Summary
    console.rule("[bold]Cleanup Summary")
    for device, res in results.items():
        if isinstance(res, dict):
            status = "[green]OK" if res.get("success") else "[yellow]Partial/Manual required"
            console.print(f"  {device:20s}: {status}")
            detail = res.get("detail", "")
            if detail:
                console.print(f"    {detail[:200]}")
        else:
            for log_type, r in res.items():
                status = "[green]OK" if r.get("success") else "[yellow]Check logs"
                console.print(f"  {device}/{log_type:10s}: {status}")

    console.print("\n[bold green]Phase 4 complete.")
    return results


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    config = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    force  = "--force" in sys.argv
    run(config, force=force)
