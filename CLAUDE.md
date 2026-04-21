# FortiGate Rule Optimization Lab — Project Guide

## Project Overview

This project is a four-phase lab automation tool that demonstrates firewall policy hygiene using the Fortinet Security Fabric. It generates intentionally flawed firewall rules, produces realistic traffic to exercise those rules, then runs three parallel analysis engines — FortiOS native, FortiAnalyzer, and AI models (GPT-4o and Claude) — to identify unused, shadowed, and redundant policies.

The Python automation tool drives the data-generation side of a five-lab workshop. The lab guides in `lab_guides/` describe the instructor-led exercises that use this data.

---

## Repository Structure

```
config.yaml              # All credentials, IPs, API tokens, and tunable parameters
main.py                  # Orchestrator CLI — entry point for all phases
phase1_rule_gen.py       # Generate and push firewall rules to FortiGate via REST API
phase2_traffic.py        # Traffic generation (Scapy-based, both directions)
phase3_analysis.py       # Hit-count queries + AI model analysis (OpenAI + Anthropic)
phase4_cleanup.py        # Delete test-tagged logs from FortiGate and FortiAnalyzer
requirements.txt         # Python dependencies

lab_guides/
  prerequisites.md       # Environment prerequisites before starting Lab 1
  Network Topology.md    # IP addressing and component roles
  Lab1.md                # Base deployment and Security Fabric registration
  Lab2.md                # Traffic generation and log analytics pipeline
  Lab3.md                # AI-assisted policy hygiene
  Lab4.md                # Natural language to config with Script Assistant
  Lab5.md                # Multi-device policy consolidation with Policy Blocks
  images/
    network_topology.png # Network diagram

scenario.md              # Full scenario specification (source of truth for design intent)
```

---

## Network Topology

| Component       | Role                          | IP / Interface                        |
|-----------------|-------------------------------|---------------------------------------|
| **FortiGate**   | Firewall under test           | port1 (inside) `192.168.1.4/24`, port2 (outside) `10.10.0.4/24`, mgmt `172.16.0.4/24` |
| **FortiAnalyzer** | Log aggregation + reporting | mgmt `172.16.0.5/24`                  |
| **FortiManager** | Central policy management    | mgmt `172.16.0.6/24`                  |
| **linux1**      | Inside traffic source         | `192.168.1.100` + aliases `.101–.110` |
| **linux2**      | Outside traffic source        | `10.10.0.100` + aliases `.101–.110`   |

IP aliases on each Linux host simulate multiple distinct source/destination hosts so traffic patterns look realistic rather than single-host.

All FortiOS components run version **8.0**. The tool targets FortiOS REST API v2.

---

## Phase 1 — Rule Generation

**Module:** `phase1_rule_gen.py`

Generates N firewall policies and pushes them to FortiGate via REST API. Policies are distributed across four deliberate overlap/redundancy patterns:

| Pattern | Description |
|---------|-------------|
| **Shadow rules** | A broad rule (`ANY ANY permit TCP 80`) followed by a narrower rule covering the same traffic — the narrower rule is permanently unreachable. |
| **Duplicate rules** | Identical `src/dst/service/action`, different policy names and IDs — simulates copy-paste accumulation. |
| **Overlapping subnets** | A `/24` permit rule coexists with `/32` or `/28` rules for hosts inside that `/24`. The broader rule makes narrower ones redundant. |
| **Same src/dst, different services** | Multiple rules between identical address pairs (TCP 80, TCP 443, UDP 53, ICMP) that could be collapsed into a single rule with a service group. |

Distribution: ~30–40% of rules are clean (to make overlap non-obvious), ~60–70% contain at least one overlap pattern.

All generated policies are tagged with the comment `LAB-TEST-2025` for later filtering and cleanup.

**Services covered:** TCP 80, 443, 8080, 8443, 22, 25, 3306, random high ports; UDP/TCP 53 (DNS); ICMP.

---

## Phase 2 — Traffic Generation

**Module:** `phase2_traffic.py`

Generates low-volume, log-observable traffic from both Linux hosts using Scapy (primary) and hping3 (supplementary). Requires root for raw socket access.

Traffic intentionally matches **60–75%** of configured rules, leaving 25–40% with zero hit counts — those are the candidates for unused-rule detection.

**Traffic types:**
- TCP SYN/ACK flows to varied destination ports
- ICMP echo requests across multiple src/dst alias pairs
- HTTP GET requests (layer 7) for application-layer log entries
- DNS queries (UDP 53)

Each session uses a unique 5-tuple to maximize log diversity. Pacing is controlled by `inter_packet_delay` and `inter_session_delay` in `config.yaml`.

IP aliases must be configured on each host before running traffic:

```bash
sudo python3 main.py traffic --setup-aliases   # run once on each host
```

---

## Phase 3 — Analysis

**Module:** `phase3_analysis.py`

Three parallel analysis paths run after the observation window:

**A. FortiGate built-in hit counts**
- Queries `/api/v2/monitor/firewall/policy/` for per-policy hit counts
- Flags any policy with `hit_count = 0` as unused

**B. FortiAnalyzer log query**
- Queries FAZ API for traffic logs filtered by the `LAB-TEST-2025` tag
- Aggregates by policy ID, identifies IDs with no log entries

**C. AI-based optimization**
- Exports full rule set as structured JSON + hit count report
- Sends both to **GPT-4o** (`openai_model` in config) and **Claude** (`anthropic_model` in config)
- Both model outputs are saved separately under `lab_output/`
- A diff report is generated comparing GPT-4o vs. Claude recommendations

Each AI prompt requests: unused rule identification, merge candidates (collapsible service groups), shadow rule identification, and a recommended consolidated rule set.

---

## Phase 4 — Cleanup

**Module:** `phase4_cleanup.py`

Deletes only test-generated artifacts:
- **FortiGate:** purges policies where comment matches `LAB-TEST-2025`
- **FortiAnalyzer:** deletes log entries filtered by the same tag and test time window

Does **not** touch any pre-existing policies or logs.

---

## CLI Reference

All phases are driven through `main.py`. Run from the project root.

```bash
# Phase 1: Generate and push 500 rules
python3 main.py rules --count 500

# Phase 1: Dry run (generate locally, skip API push)
python3 main.py rules --count 500 --dry-run

# Phase 1: Delete all lab rules from FortiGate
python3 main.py rules --delete

# Phase 2: Add IP aliases to this host (run once, as root)
sudo python3 main.py traffic --setup-aliases

# Phase 2: Inside → outside traffic (run on linux1)
sudo python3 main.py traffic --direction in2out

# Phase 2: Outside → inside traffic (run on linux2)
sudo python3 main.py traffic --direction out2in

# Phase 2: Bidirectional, limited sessions
sudo python3 main.py traffic --direction both --sessions 200

# Phase 3: Run all analysis paths
python3 main.py analyze

# Phase 4: Delete test logs (prompts for confirmation)
python3 main.py cleanup

# Phase 4: Delete test logs without confirmation
python3 main.py cleanup --force

# Run phases 1 → 2 → 3 in sequence (cleanup not included)
python3 main.py all --count 500 --sessions 300

# Full reset: delete all lab rules AND all lab logs
python3 main.py reset
```

All commands accept `--config <path>` to point at a non-default config file.

---

## Configuration

Copy `config.yaml` and fill in the `REPLACE_ME` values before running.

| Key | Description |
|-----|-------------|
| `fortigate.host` | FortiGate management IP |
| `fortigate.api_token` | REST API token (FortiOS: System > API Tokens) |
| `fortigate.vdom` | Target VDOM (default: `root`) |
| `fortianalyzer.host` | FortiAnalyzer management IP |
| `fortianalyzer.api_token` | FAZ API token (System Settings > Admin > API) |
| `fortianalyzer.adom` | ADOM containing the FortiGate |
| `ai.openai_api_key` | OpenAI API key (`sk-...`) |
| `ai.anthropic_api_key` | Anthropic API key (`sk-ant-...`) |
| `traffic.match_ratio` | Fraction of rules to match with traffic (0.60–0.75) |
| `lab.tag` | Tag applied to all generated rules/logs (`LAB-TEST-2025`) |
| `lab.observation_window_hours` | Window for unused-rule detection (default: 24) |

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.yaml config.local.yaml   # fill in credentials
```

Phase 2 (traffic generation) additionally requires `hping3` installed on the Linux hosts.

---

## Lab Guide Summary

The `lab_guides/` directory contains a five-lab instructor-led workshop that uses this tool:

| Lab | Title | Purpose |
|-----|-------|---------|
| Lab 1 | Base Deployment & Security Fabric Registration | Deploy FortiGate, FortiManager, FortiAnalyzer; enable FortiAI Assist |
| Lab 2 | Traffic Generation & Log Analytics Pipeline | Run this tool; verify FAZ log ingestion; build policy hit-count reports |
| Lab 3 | AI-Assisted Policy Hygiene | Use FortiManager Policy Check + FortiAI to find unused/shadowed rules |
| Lab 4 | Natural Language to Config | Script Assistant: generate, stage, diff, install, and roll back changes |
| Lab 5 | Multi-Device Policy Consolidation | Policy Blocks + metadata variables for multi-FortiGate deployments |

This Python tool is the primary data source for Labs 2 and 3. Labs 4 and 5 build on the state left by Lab 3.

---

## Key Design Decisions

- **Tag-scoped operations:** Every generated rule and log entry is tagged `LAB-TEST-2025`. All delete/cleanup operations are strictly scoped to this tag, so pre-existing production rules are never touched.
- **Intentional incompleteness:** Traffic only matches 60–75% of rules by design. The remaining 25–40% with zero hit counts are the evidence for the unused-rule analysis.
- **Dual AI comparison:** GPT-4o and Claude outputs are saved separately and diffed. This is the core demo value — showing how two different AI engines approach the same policy optimization problem.
- **No daemon required:** Traffic generation starts and stops via CLI flags (SIGINT / Ctrl+C). No background services needed.
- **SSL verification disabled by default:** `verify_ssl: false` in config. Set to `true` in any non-lab environment with a valid certificate.
