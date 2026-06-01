# FortiGate Rule Optimization Lab — Project Guide

## Project Overview

This project is a four-phase lab automation tool that demonstrates firewall policy hygiene using the Fortinet Security Fabric. It generates intentionally flawed firewall rules, produces realistic traffic to exercise those rules, then applies two analysis approaches — traditional CIDR-based detection and interactive AI analysis via OpenCode + OpenRouter — to identify unused, shadowed, and redundant policies.

The Python automation tool drives the data-generation side of an instructor-led workshop. The lab guides in `lab_guides/` describe the exercises that use this data. Labs 1–5 are the core path; Labs 6–7 are deferred extensions that build on the state left by Lab 5.

---

## Repository Structure

```
config.yaml.example      # Template — copy to config.yaml and fill in credentials
main.py                  # Orchestrator CLI — entry point for all phases
phase1_rule_gen.py       # Generate and push firewall rules to FortiGate via REST API
phase2_traffic.py        # Traffic generation (Scapy-based, inside→outside from LinuxA)
phase3_zero.py           # Ground truth baseline — reads phase1 JSON, reports counts by _type
phase3_traditional.py    # Traditional detection — FortiGate CMDB + CIDR math (no AI)
phase4_cleanup.py        # Delete test-tagged policies and logs from FortiGate and FortiAnalyzer
requirements.txt         # Python dependencies
tests/                   # Pytest suite for phase1 / phase2

lab_guides/
  prerequisites.md       # Environment prerequisites before starting Lab 1
  Network Topology.md    # IP addressing and component roles
  Lab1.md                # Base deployment and Security Fabric registration
  Lab2.md                # Traffic generation and log analytics pipeline
  Lab3.md                # Ground truth + traditional CIDR detection
  Lab4.md                # AI analysis with OpenCode + OpenRouter
  Lab5.md                # Phase 4 cleanup
  Lab6.md                # (deferred) Natural language to config with Script Assistant
  Lab7.md                # (deferred) Multi-device policy consolidation with Policy Blocks
  images/
    network_topology.png # Network diagram

scenario.md              # Full scenario specification (source of truth for design intent)
```

---

## Network Topology

| Component        | Role                          | IP / Interface                                                        |
|------------------|-------------------------------|-----------------------------------------------------------------------|
| **FortiGate**    | Firewall under test           | port2 (inside) `192.168.1.4/24`, port1 (outside) `10.10.0.4/24`, port3 (mgmt) `172.16.0.4/24` |
| **FortiAnalyzer** *(optional)* | Log aggregation + reporting   | mgmt `172.16.0.5/24` — only used by the FAZ appendix in Lab 1 |
| **LinuxA**       | Inside traffic source         | `192.168.1.100` + aliases `.101–.110`                                 |
| **LinuxB**       | Outside traffic source        | `10.10.0.100` + aliases `.101–.110`                                   |

IP aliases on each Linux host simulate multiple distinct source/destination hosts so traffic patterns look realistic rather than single-host.

All FortiOS components run version **8.0**. The tool targets FortiOS REST API v2.

**All generated rules are inside→outside only.** LinuxA is the sole required traffic host. LinuxB is not needed.

---

## Phase 1 — Rule Generation

**Module:** `phase1_rule_gen.py`

Generates exactly N firewall policies and pushes them to FortiGate via REST API (`port2` inside → `port1` outside). Policies are distributed across four deliberate overlap/redundancy patterns:

| Pattern | Description |
|---------|-------------|
| **Shadow rules** | A broad rule followed by a narrower rule covering the same traffic — the narrower rule is permanently unreachable. Emits 2 policies per group. |
| **Duplicate rules** | Identical `src/dst/service/action`, different policy names — simulates copy-paste accumulation. Emits 2 policies per group. |
| **Overlapping subnets** | A `/24` permit rule coexists with `/32` or `/28` rules for hosts inside that `/24`. The broader rule makes narrower ones redundant. Emits 2 policies per group. |
| **Same src/dst, different services** | Multiple rules between identical address pairs that could be collapsed into a single rule with a service group. Emits 2–4 policies per group. |

**Distribution** is controlled by `rules.ratios` in `config.yaml` (see Configuration). Ratios are auto-normalized so they don't need to sum to 1. Clean rules always fill the remainder to guarantee `--count N` pushes **exactly N policies**.

**Policy naming** uses a realistic `{SRC_ZONE}-{DST_ZONE}-{SVC}-{NNNN}` format (e.g. `CORP-INET-WEB-0042`, `MGMT-WAN-SSH-0017`) that reveals nothing about the overlap type.

**FortiGate `comments` field** contains only the `LAB-TEST-2025` tag — no pattern type is visible in the UI. The `_type` field in the local JSON backup records the pattern type for reference but is stripped before the API push.

All generated policies are tagged `LAB-TEST-2025` in comments for later filtering and cleanup.

**Services covered:** TCP 80, 443, 22, 25, 3306, 3389, 21, 23, 88, 143, 110, 389, 1433, 2049; UDP 53 (DNS); ICMP; and others.

---

## Phase 2 — Traffic Generation

**Module:** `phase2_traffic.py`

Generates low-volume, log-observable traffic **from LinuxA only** using Scapy (TCP, ICMP, DNS) and raw sockets (HTTP). Requires root for raw socket access.

Traffic intentionally matches **60–75%** of configured rules (controlled by `traffic.match_ratio`), leaving 25–40% with zero hit counts — those are the candidates for unused-rule detection.

**Key behaviours:**
- Reads `lab_output/generated_rules.json` (written by Phase 1) to know which policies exist.
- Selects `match_ratio` of policies as targets. The remaining policies are intentionally skipped.
- Cycles through targets **round-robin** (reshuffled each full pass) so every targeted rule receives at least one hit before any rule receives a second hit. This prevents false zero-hit counts on target rules.
- For each session, picks src/dst IPs that **fall inside the policy's actual address objects** (parsed from the LAB address name), so traffic hits the correct FortiGate rule rather than a broader one.
- Auto-detects which side the host is on. If running on LinuxA (`--direction out2in` or `both`), it aborts or downgrades gracefully — all rules are inside→outside so out2in is not needed.

**Traffic types:**
- TCP SYN to destination port matching the policy service
- HTTP GET (raw socket, layer 7) for port 80 / 8080
- ICMP echo requests (for PING rules)
- DNS queries via UDP 53

IP aliases must be configured on LinuxA before running traffic:

```bash
source .venv/bin/activate
sudo $(which python3) main.py traffic --setup-aliases   # run once on LinuxA
```

---

## Phase 3 — Analysis

Three scripts cover different analysis approaches. Run `phase3_zero.py` first to establish the answer key, then compare.

---

### phase3_zero.py — Ground Truth Baseline

Reads `lab_output/generated_rules.json` (written by phase1) and reports exact counts per overlap type using the `_type` internal field. No FortiGate or FortiAnalyzer connection required. This is the answer key — students compare their detection results against this output.

```bash
python3 phase3_zero.py
python3 phase3_zero.py --output zero_report.json
```

---

### phase3_traditional.py — Traditional CIDR Detection

Connects to FortiGate and applies two detection passes. **No FortiAnalyzer required.**

- **Pass A — Behavioral** *(skip with `--skip-unused`)*: queries `GET /api/v2/monitor/firewall/policy` on FortiGate for per-policy `hit_count`, `bytes`, and `last_used`. Flags policies with `hit_count == 0` as unused. Requires traffic to have been generated first (Phase 2).
- **Pass B — Structural** *(always runs)*: fetches all `LAB-TEST-2025` policies + address-object CIDR map from FortiGate CMDB. Uses `ipaddress.supernet_of()` containment math to detect duplicates, shadow pairs, subnet overlaps, and collapsible service groups. No traffic required.

Output is a `traditional_report.json` with a `flagged_policies` index containing `policyid`, `srcaddr`, `dstaddr`, and `service` for every flagged rule — making the report self-contained for downstream use with OpenCode.

**Known limitation:** pure structural CIDR analysis cannot distinguish intentional overlaps (planted shadows, planned redundancy) from incidental ones that emerge in dense rule sets. On a 100-rule lab in a small /24-pair address pool, `phase3_traditional` typically reports 7–10× more shadow/subnet-overlap pairs than ground truth — every accidental superset relationship looks identical to a planted shadow. This over-counting motivates the AI analysis step in Lab 4.

```bash
python3 phase3_traditional.py                             # both passes
python3 phase3_traditional.py --skip-unused               # structural only, no traffic needed
python3 phase3_traditional.py --output traditional_report.json
```

---

### AI Analysis — OpenCode + OpenRouter (primary workflow)

The AI analysis step is handled interactively using **OpenCode** (terminal AI agent) connected to **OpenRouter** (unified model API). This replaces `phase3_analysis.py` as the primary AI workflow.

**Why this approach:**
- Model-agnostic — swap GPT-4o, Claude, Gemini, or any OpenRouter model without code changes
- Interactive — ask follow-up questions, drill into specific rules, iterate on the consolidated ruleset
- No API key management in code — one OpenRouter key, configured in OpenCode
- `report.json` is self-contained — the `flagged_policies` index includes `policyid`, `srcaddr`, `dstaddr`, and `service` for every flagged rule so no extra API calls are needed

**Workflow:**

```bash
# 1. Generate the reports (automated)
python3 phase3_zero.py --output zero_report.json
python3 phase3_traditional.py --skip-unused --output traditional_report.json

# 2. Hand off to OpenCode (interactive)
opencode
```

**Starter prompt for the OpenCode session:**

```
Read traditional_report.json and zero_report.json.

traditional_report.json was produced by a CIDR-based detection script.
zero_report.json is the ground truth (every rule's actual type is known).

Tasks:
1. Compare counts per issue type and calculate detection accuracy (detected / actual).
2. Explain what the traditional script missed and why (focus on shadow and subnet-overlap blind spots).
3. For each collapsible service group in flagged_policies, write a single merged FortiGate
   REST API payload that replaces the group with one rule using a service group object.
4. For each duplicate group, identify which policy to keep (lowest policyid) and which to delete.
```

---

## Phase 4 — Cleanup

**Module:** `phase4_cleanup.py`

Deletes only test-generated artifacts:
- **FortiGate:** purges policies where comment matches `LAB-TEST-2025` (always runs)
- **FortiAnalyzer:** deletes log entries filtered by the same tag and test time window (only runs if a `fortianalyzer:` block is present in `config.yaml` — skipped automatically otherwise)

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

# Phase 2: Add IP aliases to LinuxA (run once, as root)
source .venv/bin/activate && sudo $(which python3) main.py traffic --setup-aliases

# Phase 2: Generate traffic inside→outside (run on LinuxA)
sudo $(which python3) main.py traffic --direction in2out

# Phase 2: Limited session count
sudo $(which python3) main.py traffic --direction in2out --sessions 200

# Phase 3: Ground truth baseline only (no FortiGate needed)
python3 main.py analyze --zero

# Phase 3: Traditional CIDR detection only (requires FortiGate)
python3 main.py analyze --traditional

# Phase 3: Traditional — structural only, skip unused detection (no traffic needed)
python3 main.py analyze --traditional --skip-unused

# Phase 3: Both reports (default when no flag given)
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

Copy `config.yaml.example` to `config.yaml` and fill in the `REPLACE_ME` values before running.

| Key | Description |
|-----|-------------|
| `fortigate.host` | FortiGate inside-interface IP (`192.168.1.4` on `port2`) — reachable from Linux Host A on the inside network |
| `fortigate.inside_interface` | FortiGate inside interface (default: `port2`) |
| `fortigate.outside_interface` | FortiGate outside interface (default: `port1`) |
| `fortigate.api_token` | REST API token (FortiOS: System > API Tokens) |
| `fortigate.vdom` | Target VDOM (default: `root`) |
| `fortianalyzer.*` | **Optional.** Only needed if FortiAnalyzer is deployed (Lab 1 appendix) and Phase 4 should also purge FAZ log entries. Leave the block commented out for the FortiGate-only path. |
| `network.inside.subnets` | List of subnets used by Phase 1 to generate inside address objects. Default: `["192.168.1.0/24"]`. Keep a single `/24` in cloud environments (anti-spoofing blocks traffic to unrouted addresses); add more subnets for on-prem labs with additional routed networks. |
| `network.outside.subnets` | Same as above for the outside network. Default: `["10.10.0.0/24"]`. |
| `traffic.match_ratio` | Fraction of rules to match with traffic (0.60–0.75) |
| `rules.ratios.shadow` | Fraction of total policies that are shadow-rule pairs (default: 0.20) |
| `rules.ratios.duplicate` | Fraction of total policies that are duplicate pairs (default: 0.15) |
| `rules.ratios.subnet_overlap` | Fraction of total policies that are subnet-overlap pairs (default: 0.15) |
| `rules.ratios.service_overlap` | Fraction of total policies that are collapsible service groups (default: 0.15) |
| `rules.ratios.clean` | Fraction of total policies that are clean rules (default: 0.35) |
| `lab.tag` | Tag applied to all generated rules/logs (`LAB-TEST-2025`) |

Ratios are auto-normalized — they do not need to sum to 1.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml   # fill in credentials
```

---

## Lab Guide Summary

The `lab_guides/` directory contains the workshop. Labs 1–5 are the active path; Labs 6–7 are deferred and not part of the current workshop scope.

| Lab | Title | Purpose |
|-----|-------|---------|
| Lab 1 | Base Deployment & API Token Setup | Deploy FortiGate; create the REST API token used by the lab tool |
| Lab 2 | Rule Generation, Traffic & Hit-Count Verification | Phase 1 (push 100 rules) + Phase 2 (traffic from LinuxA) + FortiGate monitor-API hit-count check |
| Lab 3 | Policy Analysis — Ground Truth & Traditional CIDR Detection | Phase 3 (zero + traditional scripts); compare detection accuracy |
| Lab 4 | AI Analysis with OpenCode + OpenRouter | Install OpenCode on LinuxA; run 5 AI analysis scenarios against JSON reports |
| Lab 5 | Lab Cleanup | Phase 4: delete lab rules from FortiGate; remove LinuxA aliases; (optional) clean FAZ logs |
| Lab 6 *(deferred)* | Natural Language to Config | Script Assistant: generate, stage, diff, install, and roll back changes |
| Lab 7 *(deferred)* | Multi-Device Policy Consolidation | Policy Blocks + metadata variables for multi-FortiGate deployments |

This Python tool is the primary data source for Labs 2–5.

---

## Key Design Decisions

- **Tag-scoped operations:** Every generated rule and log entry is tagged `LAB-TEST-2025`. All delete/cleanup operations are strictly scoped to this tag, so pre-existing production rules are never touched.
- **Intentional incompleteness:** Traffic only matches 60–75% of rules by design. The remaining 25–40% with zero hit counts are the evidence for the unused-rule analysis.
- **Exact policy count:** `--count N` always pushes exactly N policies. Shadow, duplicate, and subnet-overlap types emit 2 policies per group; service-overlap is capped to avoid overshoot; clean rules fill the remainder.
- **Config-driven ratios:** Overlap type distribution is set in `rules.ratios` in `config.yaml` — no code changes needed to tune the lab scenario.
- **Config-driven address pool:** Phase 1 generates address objects only from `network.inside.subnets` and `network.outside.subnets`. Host `/32` objects come from the configured aliases. This ensures every rule target is reachable by the traffic generator — required in cloud environments where the hypervisor drops packets to/from unrouted addresses.
- **Realistic policy names:** Names follow `{SRC_ZONE}-{DST_ZONE}-{SVC}-{NNNN}` (e.g. `CORP-INET-WEB-0042`). The overlap type is stored in the local JSON backup (`_type` field) but never pushed to FortiGate and never visible in the UI.
- **Address-aware traffic:** Phase 2 resolves each policy's `srcaddr`/`dstaddr` objects to real IPs, ensuring packets hit the correct FortiGate rule rather than a broader catch-all.
- **Round-robin target cycling:** Phase 2 cycles through target rules in shuffled order, guaranteeing every targeted rule receives at least one hit before repeating. This prevents false zero-hit counts within the matched set.
- **LinuxA-only operation:** All generated rules are inside→outside. Everything can be run by SSH-ing into LinuxA alone. The `out2in` direction is auto-detected and rejected with a clear message if attempted from LinuxA.
- **OpenCode + OpenRouter for AI analysis:** The AI analysis step uses OpenCode (terminal agent) connected to OpenRouter rather than a Python script. This keeps the codebase simple, allows any model to be used without code changes, and enables interactive follow-up rather than static text output. `report.json` is enriched with full policy details so the AI session is self-contained.
- **No daemon required:** Traffic generation starts and stops via CLI flags (SIGINT / Ctrl+C). No background services needed.
- **SSL verification disabled by default:** `verify_ssl: false` in config. Set to `true` in any non-lab environment with a valid certificate.
