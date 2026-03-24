# Scenario Summary

## Infrastructure

| Component       | Role                          | IP                                        |
|-----------------|-------------------------------|-------------------------------------------|
| linux1          | Inside host / traffic source  | `192.168.1.100` (primary) + aliases       |
| linux2          | Outside host / traffic source | `10.10.0.100` (primary) + aliases         |
| FortiGate       | Firewall under test           | TBD via config file                       |
| FortiAnalyzer   | Log aggregation + analysis    | TBD via config file                       |

Linux1 and linux2 will each have virtual IP aliases added to their interfaces (e.g., `192.168.1.101–110`, `10.10.0.101–110`) to simulate multiple hosts and make rules and traffic patterns appear realistic rather than a single-host test.

---

## Phase 1 — Rule Generation (FortiGate API)

The user inputs a rule count (e.g., 1000). The generator produces that many firewall policies via the FortiGate REST API, distributed across a target VDOM, with four deliberate overlap/redundancy patterns embedded throughout.

### Overlap Types Injected

| Type | Description |
|------|-------------|
| **Shadow rules** | Policies placed after a broader rule that already matches the same traffic, making them permanently unreachable. E.g., `src ANY dst ANY permit TCP 80` followed by `src 192.168.1.0/24 dst 10.10.0.0/24 permit TCP 80`. |
| **Duplicate rules** | Identical `src/dst/service/action`, different policy names and IDs. Simulates copy-paste accumulation over time. |
| **Overlapping subnet ranges** | A `/24` permit rule coexists with one or more `/32` or `/28` rules covering hosts within that same `/24`. The broader rule makes the narrower ones redundant. |
| **Same src/dst, different services** | Multiple rules between the same address pairs for TCP 80, TCP 443, UDP 53, ICMP, etc. that could be collapsed into a single rule with a service group. |

All generated policies are tagged with a consistent comment/label (`LAB-TEST-2025`) to make them identifiable for later log filtering and cleanup.

### Rule Distribution (Protocols/Services)

- TCP — varied ports: `80`, `443`, `8080`, `8443`, `22`, `25`, `3306`, random high ports
- HTTP/HTTPS — tied to application control objects where applicable
- DNS — `UDP 53` / `TCP 53`
- ICMP

Approximately **30–40%** of rules will be clean/non-overlapping (to make the overlap non-obvious and realistic). The remaining **60–70%** will contain one or more of the four overlap patterns.

---

## Phase 2 — Traffic Generation

Traffic is generated from both directions. The goal is **low-volume, log-observable traffic** — not load testing.

- `linux1 → linux2` (inside to outside)
- `linux2 → linux1` (outside to inside)

**Tools:** Scapy (primary, Python-native) + hping3 (supplementary for TCP flag variation).

Traffic will intentionally match **60–75%** of the configured rules, leaving **25–40%** of rules with zero hit counts — those are the candidates for unused rule detection in Phase 3.

### Traffic Patterns Generated

- TCP SYN/ACK flows to varied destination ports matching rule service definitions
- ICMP echo requests across multiple src/dst alias pairs
- HTTP GET requests (layer 7, via `requests` or raw Scapy HTTP) to trigger application-layer log entries
- DNS queries (UDP 53) to simulate real resolver traffic

Traffic is paced with a configurable inter-packet delay to keep logs readable and avoid overwhelming FortiAnalyzer. Each session logs a unique 5-tuple to maximize log diversity.

Start/stop is controlled via a CLI flag — no daemon required.

---

## Phase 3 — Unused Rule Detection

After a configurable observation window (e.g., 24–48 hours, or manually triggered), three parallel analysis paths run.

### A. FortiGate Built-in Optimization

- Query FortiGate API for per-policy hit counts (`/api/v2/monitor/firewall/policy/`)
- Pull policy usage statistics directly from FortiOS
- Flag any policy with `hit_count = 0` since test start as unused
- Also call FortiGate's native policy analysis endpoint if available (FortiOS 7.6/8.0)

### B. FortiAnalyzer Query

- Query FortiAnalyzer API for log entries filtered by the `LAB-TEST-2025` tag
- Aggregate by policy ID
- Identify policy IDs with no log entries in the observation window
- Cross-reference against the full rule list to produce an unused rule list

### C. AI-based Optimization (OpenAI + Anthropic)

- Export the full rule set as structured JSON
- Export the hit count / usage report
- Send both to **GPT-4o** and **Claude** (`claude-sonnet-4-6`) with a structured prompt requesting:
  - Identification of unused rules
  - Identification of rules that can be merged (same src/dst, collapsible services)
  - Identification of shadow rules
  - Recommended consolidated rule set
- Both model outputs are saved separately for comparison
- A diff report is generated between GPT-4o and Claude recommendations

---

## Phase 4 — Log Cleanup

Deletes only logs attributable to this test:

- **FortiGate:** purge log entries where policy comment matches `LAB-TEST-2025`
- **FortiAnalyzer:** delete log entries filtered by the same tag + time window of the test
- Does **NOT** touch pre-existing logs

---

## Code Structure

Six discrete Python modules + one config file:

```
config.yaml              # All IPs, credentials, VDOM, interface names, API tokens
phase1_rule_gen.py       # Generate + push rules to FortiGate via API
phase2_traffic.py        # Traffic generation (start/stop, both directions)
phase3_analysis.py       # Hit count queries, FortiAI, OpenAI, Anthropic analysis
phase4_cleanup.py        # Log deletion scoped to test tag
main.py                  # Orchestrator CLI — runs phases, accepts flags
requirements.txt         # All Python dependencies
```

---

## What This Demonstrates

At the end of the exercise you will have a measurable, evidence-backed answer to:

> *"Of N firewall rules, X% were never matched in Y days — and here is what three different optimization engines (FortiOS native, GPT-4o, Claude) each recommend doing about it."*
