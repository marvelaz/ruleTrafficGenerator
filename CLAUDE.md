# CLAUDE.md — FortiGate Rule Optimization Lab

## Project Overview

This project is a Python-based lab framework for security engineers to simulate, measure, and optimize
firewall policy bloat on a FortiGate appliance backed by FortiAnalyzer for log aggregation.

Primary users are network security engineers and firewall administrators who need to demonstrate —
with real traffic evidence — that accumulated firewall rules contain significant redundancy, and that
multiple optimization engines (FortiOS native, FortiAI, OpenAI, Anthropic) can be used to produce a
curated, reduced ruleset.

The product optimizes for:
- Realism: rules and traffic must look like genuine enterprise configuration drift, not synthetic noise
- Evidence quality: every unused rule conclusion must be backed by hit-count data from two independent
  sources (FortiGate API and FortiAnalyzer logs)
- Modularity: each phase (rule gen, traffic, analysis, cleanup) runs independently or chained
- Auditability: all generated objects are tagged LAB-TEST-2025 so nothing touches pre-existing config
- Comparability: OpenAI and Anthropic recommendations are produced from identical inputs and diffed

Avoid over-engineering. Prefer explicit over implicit. Each phase module must be runnable standalone.


## Infrastructure

```
linux1 (192.168.1.100) ── inside ──┐
                                   FortiGate (7.6 / 8.0)  ── outside ── linux2 (10.10.0.100)
                                        │
                                   FortiAnalyzer
```

| Component      | Role                                      | Primary IP     |
|----------------|-------------------------------------------|----------------|
| linux1         | Inside traffic source (root access)       | 192.168.1.100  |
| linux2         | Outside traffic source (root access)      | 10.10.0.100    |
| FortiGate      | Firewall under test, API target           | config.yaml    |
| FortiAnalyzer  | Log aggregation, secondary hit analysis   | config.yaml    |

Both Linux hosts have secondary IP aliases on the same interface to simulate multiple source/destination
hosts. Aliases are managed by `phase2_traffic.py --setup-aliases` and require root.


## File Structure

```
config.yaml              All environment config: IPs, tokens, VDOM, interface names, tuning params
main.py                  CLI orchestrator — entry point for all phases
phase1_rule_gen.py       Rule generation and FortiGate API push
phase2_traffic.py        Traffic generation using Scapy + raw sockets
phase3_analysis.py       Hit-count analysis: FortiGate native, FortiAnalyzer, OpenAI, Anthropic
phase4_cleanup.py        Scoped log deletion on FortiGate and FortiAnalyzer
requirements.txt         Python dependencies
lab_output/              Auto-created at runtime — all reports and JSON exports land here
```


## Phase Summary

### Phase 1 — Rule Generation (`phase1_rule_gen.py`)
- User specifies rule count (e.g. 1000)
- Generates address objects, custom service objects, and firewall policies via FortiGate REST API
- All objects tagged with comment `LAB-TEST-2025`
- Four overlap types are deliberately injected across the ruleset:
  - **Shadow rules**: a narrow rule placed after a broader rule that already matches the same traffic
  - **Duplicate rules**: identical src/dst/service/action under different policy names
  - **Overlapping subnet ranges**: /24 rule coexisting with /28 or /32 rules within the same space
  - **Same src/dst, different services**: multiple rules collapsible into a single service-group rule
- Distribution: ~35% clean rules, ~65% contain one or more overlap types
- Generated rules saved to `lab_output/generated_rules.json` before API push
- Supports `--dry-run` to inspect generated JSON without touching FortiGate

### Phase 2 — Traffic Generation (`phase2_traffic.py`)
- Loads `generated_rules.json` and selects 60-75% of rules as traffic targets (configurable via `match_ratio`)
- Remaining 25-40% of rules receive zero traffic — these become the unused rule candidates
- Protocols: TCP SYN (varied ports), ICMP echo, HTTP GET (layer 7 raw socket), DNS UDP query
- Traffic is low-volume and paced (inter-packet and inter-session delays) to keep logs readable
- Scapy used for TCP/ICMP/DNS; raw Python socket used for HTTP (to bind to specific src IP)
- Direction: `in2out` (run on linux1), `out2in` (run on linux2), or `both`
- Stopped cleanly with Ctrl+C (SIGINT handler sets a global flag, finishes current session)
- Requires root on both hosts for raw socket access

### Phase 3 — Analysis (`phase3_analysis.py`)
Three parallel paths, all run in a single `python3 main.py analyze` call:

**Path A — FortiGate Native**
- Queries `/api/v2/monitor/firewall/policy/` for per-policy hit counts
- Flags zero-hit lab policies as unused
- Calls FortiAI policy analysis endpoint (`/monitor/fortiai/policy-analysis`) — gracefully skips if unavailable

**Path B — FortiAnalyzer**
- Queries FAZ JSON-RPC API for traffic logs filtered by `LAB-TEST-2025` tag within observation window
- Aggregates by policy ID
- Cross-references against full lab policy list to identify zero-log policies

**Path C — AI Models**
- Sends trimmed policy JSON + unused policy list to OpenAI (gpt-4o) and Anthropic (claude-sonnet)
- Both receive identical system prompt and identical input payload
- Prompt requests: unused rule identification, shadow rule detection, duplicate detection,
  collapsible rule groups, and a recommended consolidated ruleset in JSON
- Outputs saved separately; a diff report is generated comparing both recommendations

### Phase 4 — Log Cleanup (`phase4_cleanup.py`)
- Deletes only logs tagged `LAB-TEST-2025` — does not touch pre-existing logs
- FortiGate: attempts filtered deletion via `/monitor/log/delete` REST endpoint
  (FortiOS 7.4+ — falls back to exact CLI commands if endpoint unavailable on this build)
- FortiAnalyzer: filtered deletion via JSON-RPC exec with tag + time window filter
- Requires explicit confirmation unless `--force` flag is passed


## Configuration (`config.yaml`)

All environment-specific values live in `config.yaml`. Never hardcode credentials or IPs in module files.

Key tuning parameters:
- `traffic.match_ratio`: controls what percentage of rules receive traffic (default 0.68 = 68%)
- `traffic.inter_packet_delay` / `inter_session_delay`: controls log density — increase for sparser logs
- `lab.observation_window_hours`: how far back FortiAnalyzer and analysis queries look
- `lab.tag`: the comment string embedded in all generated objects (default `LAB-TEST-2025`)
- `fortigate.vdom`: must match the VDOM where rules are being pushed


## API Notes

**FortiGate REST API**
- Base: `https://{host}:{port}/api/v2`
- Auth: `Authorization: Bearer {api_token}` header
- VDOM scoped via `?vdom={vdom}` query param on all requests
- Config endpoints: `/cmdb/firewall/policy`, `/cmdb/firewall/address`, `/cmdb/firewall.service/custom`
- Monitor endpoints: `/monitor/firewall/policy/` (hit counts), `/monitor/fortiai/policy-analysis`
- Rate limit: code enforces 100ms sleep between policy pushes to avoid overwhelming the API

**FortiAnalyzer JSON-RPC API**
- Base: `https://{host}:{port}/jsonrpc`
- Auth: `X-Auth-Token: {api_token}` header
- All queries scoped to ADOM via URL path `/logview/adom/{adom}/...`
- Log queries use `apiver: 3` and accept `filter`, `start-time`, `end-time`, `limit` params

**FortiOS version compatibility**
- Tested against FortiOS 7.6 and 8.0 API schemas
- FortiAI endpoint available in 7.4+ — code logs raw response for version-specific debugging
- Filtered log deletion endpoint (`/monitor/log/delete`) may return 404 on some 7.6 builds;
  fallback CLI commands are printed automatically


## AI Optimization Prompt Design

Both OpenAI and Anthropic receive the same structured system prompt requesting:
1. Unused policy identification with reasons
2. Shadow rule detection (policyid + shadowed-by reference)
3. Duplicate rule groups
4. Collapsible rule groups (same src/dst → service group candidates)
5. Recommended consolidated ruleset as JSON array
6. Summary table: original count → recommended count → reduction %

Input payload is capped at 300 policies to stay within context limits. Full policy list is always
saved to `lab_output/generated_rules.json` for manual review or re-submission with larger context windows.


## Known Constraints

- FortiGate filtered log deletion is version-dependent. If the REST endpoint is unavailable,
  `phase4_cleanup.py` prints the exact CLI commands required.
- Traffic generation requires `root` or `CAP_NET_RAW` on both Linux hosts. Running without root
  will exit with a clear error message before attempting any packet sends.
- FortiAI response schema varies between FortiOS builds. Raw response is always logged to
  `lab_output/analysis_report.json` under the `fortiai` key for inspection.
- The `--direction both` flag on `phase2_traffic.py` assumes the host running it can reach both
  inside and outside networks. In a standard two-host setup, run `in2out` on linux1 and `out2in` on linux2.
- IP aliases added by `--setup-aliases` persist across reboots unless removed with `--remove-aliases`.


## Execution Order (Standard Lab Run)

```bash
# 1. Install deps (both hosts)
pip3 install -r requirements.txt --break-system-packages

# 2. Configure
vi config.yaml   # fill in IPs, API tokens, VDOM, interface names

# 3. Add IP aliases (root, run on each Linux host once)
sudo python3 main.py traffic --setup-aliases

# 4. Generate and push rules
python3 main.py rules --count 1000

# 5. Generate traffic (run simultaneously on both hosts)
sudo python3 main.py traffic --direction in2out    # on linux1
sudo python3 main.py traffic --direction out2in    # on linux2

# 6. Wait for observation window (minimum 1h, default 24h)

# 7. Analyze
python3 main.py analyze
# outputs land in lab_output/

# 8. Cleanup logs when done
python3 main.py cleanup

# Full reset (rules + logs)
python3 main.py reset
```
