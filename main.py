"""
main.py — Lab Orchestrator CLI

Usage examples:

  # Phase 1: Generate and push 500 rules
  python3 main.py rules --count 500

  # Phase 1: Dry run (generate only, no API push)
  python3 main.py rules --count 500 --dry-run

  # Phase 1: Delete all lab rules from FortiGate
  python3 main.py rules --delete

  # Phase 2: Setup IP aliases on this host (run once per host, as root)
  sudo python3 main.py traffic --setup-aliases

  # Phase 2: Generate traffic inside→outside (run on linux1 as root)
  sudo python3 main.py traffic --direction in2out

  # Phase 2: Generate traffic outside→inside (run on linux2 as root)
  sudo python3 main.py traffic --direction out2in

  # Phase 2: Bidirectional (if running on a host that can reach both sides)
  sudo python3 main.py traffic --direction both --sessions 200

  # Phase 2: Stop traffic (send SIGINT / Ctrl+C in the running terminal)

  # Phase 3: Run analysis (all three paths)
  python3 main.py analyze

  # Phase 4: Delete lab logs (prompts for confirmation)
  python3 main.py cleanup

  # Phase 4: Delete lab logs without confirmation prompt
  python3 main.py cleanup --force

  # Run all phases in sequence (phases 1→2→3, no cleanup)
  python3 main.py all --count 500 --sessions 300

  # Full reset: delete rules + delete logs
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
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    level = getattr(logging, cfg.get("logging", {}).get("level", "INFO"))
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
              type=click.Choice(["in2out", "out2in", "both"]),
              help="Traffic direction", show_default=True)
@click.option("--sessions",       default=0,     help="Max sessions (0=unlimited)")
@click.option("--setup-aliases",  is_flag=True,  help="Add IP aliases to interface and exit")
@click.option("--remove-aliases", is_flag=True,  help="Remove IP aliases and exit")
@click.pass_context
def traffic(ctx, direction, sessions, setup_aliases, remove_aliases):
    """Phase 2: Generate traffic between linux1 and linux2."""
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
@click.pass_context
def analyze(ctx):
    """Phase 3: Analyze hit counts via FortiGate, FortiAnalyzer, and AI models."""
    from phase3_analysis import run as run_analysis
    config = ctx.obj["config"]
    run_analysis(config)


# ---------------------------------------------------------------------------
# Phase 4 — Cleanup
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def cleanup(ctx, force):
    """Phase 4: Delete test-tagged logs from FortiGate and FortiAnalyzer."""
    from phase4_cleanup import run as run_cleanup
    config = ctx.obj["config"]
    run_cleanup(config, force=force)


# ---------------------------------------------------------------------------
# Combined: Full reset
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--force", is_flag=True)
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
        console.print("Run traffic manually with: sudo python3 main.py traffic --direction both")
    else:
        console.print(f"\n[bold]Phase 2: Generating {sessions} traffic sessions...")
        from phase2_traffic import run as run_traffic
        run_traffic(config, direction="both", max_sessions=sessions)

    # Wait before analysis so logs propagate to FortiAnalyzer
    if wait > 0:
        console.print(f"\n[cyan]Waiting {wait}s for logs to propagate to FortiAnalyzer...")
        time.sleep(wait)

    # Phase 3
    console.print("\n[bold]Phase 3: Running analysis...")
    from phase3_analysis import run as run_analysis
    run_analysis(config)

    console.print("\n[bold green]All phases complete.")
    console.print("Run 'python3 main.py cleanup' when ready to purge test logs.")


if __name__ == "__main__":
    cli(obj={})
