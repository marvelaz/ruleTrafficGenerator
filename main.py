"""
main.py — Lab Orchestrator CLI

Usage examples:

  # Phase 1: Generate and push 500 rules
  python3 main.py rules --count 500

  # Phase 1: Dry run (generate only, no API push)
  python3 main.py rules --count 500 --dry-run

  # Phase 1: Delete all lab rules from FortiGate
  python3 main.py rules --delete

  # Phase 2: Setup IP aliases on LinuxA (run once, as root)
  sudo python3 main.py traffic --setup-aliases

  # Phase 2: Generate traffic inside→outside (run on LinuxA as root)
  sudo python3 main.py traffic --direction in2out

  # Phase 2: Limited session count
  sudo python3 main.py traffic --direction in2out --sessions 200

  # Phase 2: Stop traffic (send SIGINT / Ctrl+C in the running terminal)

  # Phase 3: Ground truth baseline (reads local JSON, no FortiGate needed)
  python3 main.py analyze --zero

  # Phase 3: Traditional CIDR detection (requires live FortiGate)
  python3 main.py analyze --traditional

  # Phase 3: Traditional, structural only (no traffic needed)
  python3 main.py analyze --traditional --skip-unused

  # Phase 3: Both reports (zero + traditional)
  python3 main.py analyze

  # For AI analysis, hand the generated reports to OpenCode + OpenRouter
  # (see Lab 4 in lab_guides/05-lab4.md)

  # Phase 4: Delete lab logs (prompts for confirmation)
  python3 main.py cleanup

  # Phase 4: Delete lab logs without confirmation prompt
  python3 main.py cleanup --force

  # Run phases 1 → 2 → 3 in sequence (cleanup not included)
  python3 main.py all --count 500 --sessions 300

  # Full reset: delete all lab rules AND all lab logs
  python3 main.py reset
"""

import logging
import sys
import time

import click
import yaml
from rich.console import Console

console = Console()


def _setup_logging(cfg_path: str):
    try:
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        console.print(f"[bold red]ERROR:[/bold red] config file not found: {cfg_path}")
        console.print("[yellow]Hint: copy config.yaml.example to config.yaml and fill in REPLACE_ME values.[/yellow]")
        sys.exit(1)
    level = getattr(logging, cfg.get("logging", {}).get("level", "INFO"), logging.INFO)
    log_file = cfg.get("logging", {}).get("log_file", "lab.log")
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )


@click.group()
@click.option("--config", default="config.yaml",
              help="Path to config.yaml", show_default=True)
@click.pass_context
def cli(ctx, config):
    """FortiGate Rule Optimization Lab — Orchestrator"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    _setup_logging(config)


# ---------------------------------------------------------------------------
# Phase 1 — Rules
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--count",   default=100,  help="Number of rules to generate", show_default=True)
@click.option("--dry-run", is_flag=True, help="Generate policies locally, skip API push")
@click.option("--delete",  is_flag=True, help="Delete all LAB-TEST-2025 rules from FortiGate")
@click.pass_context
def rules(ctx, count, dry_run, delete):
    """Phase 1: Generate and push firewall rules to FortiGate."""
    from phase1_rule_gen import run as run_rules, delete_lab_rules
    config = ctx.obj["config"]

    if delete:
        console.print("[bold red]Deleting all lab rules from FortiGate...")
        delete_lab_rules(config)
    else:
        console.print(f"[bold cyan]Generating {count} rules (dry_run={dry_run})...")
        metadata = run_rules(config, count, dry_run=dry_run)
        console.print(f"\n[bold green]Phase 1 complete.")
        console.print(f"  Total generated : {metadata.get('total_pushed', metadata.get('total'))}")
        if not dry_run:
            console.print(f"  Pushed          : {metadata.get('pushed', 'N/A')}")
            console.print(f"  Failed          : {metadata.get('failed', 0)}")


# ---------------------------------------------------------------------------
# Phase 2 — Traffic
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--direction", default="in2out",
              type=click.Choice(["in2out"]),
              help="Traffic direction. All lab rules are inside→outside, so only in2out is supported. "
                   "out2in/both have been removed because Linux Host B is not used.",
              show_default=True)
@click.option("--sessions",       default=0,     help="Max sessions (0=unlimited)")
@click.option("--setup-aliases",  is_flag=True,  help="Add IP aliases to interface and exit")
@click.option("--remove-aliases", is_flag=True,  help="Remove IP aliases and exit")
@click.pass_context
def traffic(ctx, direction, sessions, setup_aliases, remove_aliases):
    """Phase 2: Generate traffic between LinuxA and LinuxB."""
    import os
    if os.geteuid() != 0:
        console.print("[bold red]ERROR: Traffic generation requires root (raw socket access).")
        console.print("Run with: sudo python3 main.py traffic ...")
        sys.exit(1)

    from phase2_traffic import run as run_traffic, setup_aliases as do_aliases
    config = ctx.obj["config"]

    if setup_aliases:
        do_aliases(config, remove=False)
    elif remove_aliases:
        do_aliases(config, remove=True)
    else:
        run_traffic(config, direction=direction, max_sessions=sessions)


# ---------------------------------------------------------------------------
# Phase 3 — Analysis
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--zero",        is_flag=True, default=False,
              help="Run ground truth baseline (phase3_zero) — no FortiGate needed")
@click.option("--traditional", is_flag=True, default=False,
              help="Run traditional CIDR detection (phase3_traditional) — requires FortiGate")
@click.option("--skip-unused", is_flag=True, default=False,
              help="Pass --skip-unused to phase3_traditional (structural analysis only)")
@click.option("--output-dir",  default=None,
              help="Directory to write JSON reports (default: lab.output_dir from config)")
@click.pass_context
def analyze(ctx, zero, traditional, skip_unused, output_dir):
    """
    Phase 3: Detect policy issues using ground truth and/or traditional CIDR analysis.

    With no flags, runs both --zero and --traditional.
    For AI analysis, hand the generated report.json to OpenCode + OpenRouter.
    """
    import yaml
    from pathlib import Path

    config = ctx.obj["config"]
    with open(config) as f:
        cfg = yaml.safe_load(f)

    out_dir = Path(output_dir or cfg["lab"]["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    both_default    = not zero and not traditional
    run_zero        = zero or both_default
    run_traditional = traditional or both_default

    if run_zero:
        console.rule("[bold cyan]Phase 3 — Zero: Ground Truth Baseline")
        from phase3_zero import load_rules, analyze as zero_analyze, print_report, build_json_report
        rules_file = str(Path(cfg["lab"]["output_dir"]) / cfg["lab"]["rules_backup_file"])
        policies, metadata = load_rules(rules_file)
        results = zero_analyze(policies)
        print_report(policies, metadata, results)
        out_path = out_dir / "zero_report.json"
        report = build_json_report(metadata, results)
        out_path.write_text(__import__("json").dumps(report, indent=2))
        console.print(f"\n[green]Zero report saved: {out_path}")

    if run_traditional:
        console.rule("[bold cyan]Phase 3 — Traditional: CIDR Detection")
        from phase3_traditional import (
            FortiGateAPI, run_behavioral_pass,
            run_structural_pass, print_report as trad_print, build_json_report as trad_json,
        )
        from typing import Optional

        fgt = FortiGateAPI(cfg["fortigate"])
        lab_policies = fgt.get_all_lab_policies()
        if not lab_policies:
            console.print(f"[bold red]No LAB-TEST-2025 policies found on FortiGate. Run phase1 first.")
        else:
            addr_map = fgt.get_address_map()

            behavioral: Optional[dict] = None
            if not skip_unused:
                behavioral = run_behavioral_pass(fgt, lab_policies)

            structural = run_structural_pass(lab_policies, addr_map)
            trad_print(lab_policies, structural, behavioral)

            out_path = out_dir / "traditional_report.json"
            report = trad_json(structural, behavioral)
            out_path.write_text(__import__("json").dumps(report, indent=2))
            console.print(f"\n[green]Traditional report saved: {out_path}")
            console.print(
                "\n[dim]For AI analysis: open OpenCode and run:\n"
                f"  'Read {out_dir}/traditional_report.json and {out_dir}/zero_report.json "
                "and compare detection accuracy per issue type.'[/dim]"
            )


# ---------------------------------------------------------------------------
# Phase 4 — Cleanup
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def cleanup(ctx, force):
    """Phase 4: Delete test-tagged logs from FortiAnalyzer."""
    from phase4_cleanup import run as run_cleanup
    config = ctx.obj["config"]
    run_cleanup(config, force=force)


# ---------------------------------------------------------------------------
# Combined: Full reset
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def reset(ctx, force):
    """Delete all lab rules AND all lab logs (full reset)."""
    from phase1_rule_gen import delete_lab_rules
    from phase4_cleanup import run as run_cleanup
    config = ctx.obj["config"]

    console.rule("[bold red]FULL RESET")
    delete_lab_rules(config)
    run_cleanup(config, force=force)
    console.print("[bold green]Reset complete.")


# ---------------------------------------------------------------------------
# Combined: Run all phases
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--count",    default=100, help="Number of rules to generate")
@click.option("--sessions", default=200, help="Number of traffic sessions")
@click.option("--wait",     default=60,  help="Seconds to wait between traffic and analysis")
@click.pass_context
def all(ctx, count, sessions, wait):
    """
    Run phases 1 → 2 → 3 in sequence.
    Phase 4 (cleanup) is NOT run automatically — call 'cleanup' separately.

    NOTE: Traffic generation (phase 2) runs for --sessions count then stops.
          For realistic hit-count data, run traffic for longer before analyzing.
    """
    import os
    config = ctx.obj["config"]

    console.rule("[bold cyan]Full Lab Run")

    # Phase 1
    console.print(f"\n[bold]Phase 1: Generating {count} rules...")
    from phase1_rule_gen import run as run_rules
    run_rules(config, count)

    # Phase 2
    if os.geteuid() != 0:
        console.print("\n[yellow]WARNING: Not running as root — skipping Phase 2 (traffic).")
        console.print("Run traffic manually with: sudo python3 main.py traffic --direction in2out")
    else:
        console.print(f"\n[bold]Phase 2: Generating {sessions} traffic sessions...")
        from phase2_traffic import run as run_traffic
        run_traffic(config, direction="in2out", max_sessions=sessions)

    # Wait before analysis so logs propagate to FortiAnalyzer
    if wait > 0:
        console.print(f"\n[cyan]Waiting {wait}s for logs to propagate to FortiAnalyzer...")
        time.sleep(wait)

    # Phase 3
    import yaml
    from pathlib import Path

    with open(config) as f:
        cfg = yaml.safe_load(f)

    out_dir = Path(cfg["lab"]["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    console.rule("[bold cyan]Phase 3 — Zero: Ground Truth Baseline")
    from phase3_zero import load_rules, analyze as zero_analyze, print_report, build_json_report
    rules_file = str(Path(cfg["lab"]["output_dir"]) / cfg["lab"]["rules_backup_file"])
    policies, metadata = load_rules(rules_file)
    results = zero_analyze(policies)
    print_report(policies, metadata, results)
    out_path = out_dir / "zero_report.json"
    report = build_json_report(metadata, results)
    out_path.write_text(__import__("json").dumps(report, indent=2))
    console.print(f"\n[green]Zero report saved: {out_path}")

    console.rule("[bold cyan]Phase 3 — Traditional: CIDR Detection")
    from phase3_traditional import (
        FortiGateAPI, run_behavioral_pass,
        run_structural_pass, print_report as trad_print, build_json_report as trad_json,
    )
    from typing import Optional

    fgt = FortiGateAPI(cfg["fortigate"])
    lab_policies = fgt.get_all_lab_policies()
    if not lab_policies:
        console.print("[bold red]No LAB-TEST-2025 policies found on FortiGate.")
    else:
        addr_map = fgt.get_address_map()
        behavioral: Optional[dict] = None
        behavioral = run_behavioral_pass(fgt, lab_policies)
        structural = run_structural_pass(lab_policies, addr_map)
        trad_print(lab_policies, structural, behavioral)
        out_path = out_dir / "traditional_report.json"
        report = trad_json(structural, behavioral)
        out_path.write_text(__import__("json").dumps(report, indent=2))
        console.print(f"\n[green]Traditional report saved: {out_path}")

    console.print("\n[bold green]All phases complete.")
    console.print("Run 'python3 main.py cleanup' when ready to purge test logs.")


if __name__ == "__main__":
    cli(obj={})
