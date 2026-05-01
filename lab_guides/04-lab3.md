# Lab 3: Policy Analysis — Ground Truth & Traditional CIDR Detection

In this lab you run two Python analysis passes against the 100-rule set generated in Lab 2:

1. **`phase3_zero`** — reads the local JSON written by Phase 1 and reports the *exact* count of every overlap type using the embedded `_type` field. This is the **answer key**.
2. **`phase3_traditional`** — connects to FortiGate and detects issues using only the FortiGate REST API: hit counts from the monitor endpoint and CIDR containment math from the CMDB. No `_type` field, no local JSON. This is what a real engineer would write without ground-truth metadata.

At the end you will know which issue types `phase3_traditional` detects reliably and which it systematically misses — that gap is the motivation for Lab 4 (AI analysis with OpenCode).

------

## Objectives

- Run the ground truth baseline (`phase3_zero`) to establish the answer key.
- Run the traditional CIDR detection (`phase3_traditional`).
- Compare the two reports and quantify which issue types the traditional script misses.

------

## Time to Complete

**Estimated: 25–35 minutes**

------

# Exercise 1: Phase 3 — Ground Truth Baseline (phase3_zero)

This script reads the local JSON backup written by Phase 1. It knows the exact type of every rule (`_type` field) and reports counts per category. No FortiGate connection required. **This is the answer key.**

## Task 1: Run the Ground Truth Report

On Linux Host A:

```bash
cd ~/ruleTrafficGenerator
source .venv/bin/activate
python3 main.py analyze --zero
```

Expected output (your numbers will differ slightly — counts depend on `rules.ratios` in `config.yaml` and on rounding when each pattern emits 2+ policies per group):

```
────────── Phase 3 — Zero: Ground Truth Baseline ──────────
Rules file contains 100 policies total.

┌─ Rule Type Summary ──────────────────────────────────────────────────┐
│ Group               │ Type                │ Count │                  │
│ Shadow Rules        │ Broad (catches)     │  ~10  │                  │
│ Shadow Rules        │ Narrow (unreachable)│  ~10  │                  │
│ Duplicate Rules     │ Exact copy          │  ~14  │                  │
│ Subnet Overlap      │ Broad /24           │   ~7  │                  │
│ Subnet Overlap      │ Specific /28-/32    │   ~7  │                  │
│ Collapsible Svc     │ One svc per rule    │  ~17  │                  │
│ Clean Rules         │ No overlap          │  ~35  │                  │
└──────────────────────────────────────────────────────────────────────┘

Total: 100 rules — ~35 clean, ~65 with overlap/redundancy issues

Zero report saved: lab_output/zero_report.json
```

> **Counts vs. groups.** The numbers above are **policies** (each duplicate group emits 2 policies, so ~14 duplicate policies ≈ ~7 duplicate *groups*). `phase3_traditional` in Exercise 2 reports *groups*, so its duplicate count will be roughly half of what you see here. Both views are correct — just measuring different things.

> Record the actual numbers from your run — you will compare them against the traditional detection output in the next task.

------

## Task 2: Review the JSON Report

```bash
cat lab_output/zero_report.json
```

Key fields (numbers are illustrative — yours will vary by a few units):

```json
{
  "source": "phase3_zero",
  "metadata": { "total_pushed": 100, "shadow": 20, "duplicate": 14, ... },
  "counts": {
    "shadow-broad": 10, "shadow-specific": 10,
    "duplicate": 14,
    "subnet-overlap-broad": 7, "subnet-overlap-specific": 7,
    "svc-overlap": 17,
    "clean": 35
  },
  "shadow_pairs": [ {"broad": "CORP-INET-WEB-0042", "shadowed": "CORP-INET-WEB-0019"}, ... ],
  "duplicate_groups": [ ["MGMT-WAN-PING-0007", "MGMT-WAN-PING-0051"], ... ],
  "service_overlap_groups": [ [...], ... ],
  "subnet_overlap_pairs": [ {"broad": "...", "specific": "..."}, ... ]
}
```

> `counts.duplicate` is the total number of duplicate **policies** (~14). `duplicate_groups` is the list of **groups** (~7), each containing 2 policies. The same broad/specific split applies to `shadow_*` and `subnet-overlap_*`.

> Keep this file open. It is the reference you compare every other detection method against.

------

# Exercise 2: Phase 3 — Traditional CIDR Detection (phase3_traditional)

This script detects issues using only what is visible from the FortiGate API — no `_type` field, no local JSON. It runs two passes:

- **Pass A — Behavioral:** queries `GET /api/v2/monitor/firewall/policy` for hit counts. Policies with `hit_count == 0` are flagged unused.
- **Pass B — Structural:** fetches all LAB policies and address objects, then uses CIDR containment math to detect duplicates, shadow pairs, subnet overlaps, and collapsible service groups.

## Task 1: Run Structural Analysis Only (no traffic needed)

```bash
python3 main.py analyze --traditional --skip-unused
```

Expected output (numbers are approximate — yours will vary by a few units):

```
Pass B — Structural: CIDR containment analysis
  Policies analysed       : 100
  Duplicate groups        :  ~7   ← number of groups, not policies
  Shadow pairs            :  ~5   ← roughly half detected (see note below)
  Subnet-overlap pairs    :  ~4   ← also roughly half detected
  Collapsible svc groups  :  ~8

Traditional report saved: lab_output/traditional_report.json
```

> **`phase3_traditional` reports groups; `phase3_zero` reports policies.** A duplicate "group" is a set of 2+ policies sharing identical src/dst/service. A shadow/subnet-overlap "pair" is the broad rule plus its shadowed narrow rule. So if `phase3_zero` gave you 14 duplicate policies, expect ~7 duplicate groups here. They're not in conflict — they're two views of the same data.

> **Known blind spot:** Shadow and subnet-overlap detection is position-dependent — the broad rule must appear before the narrow rule in FortiGate's sequence. Phase 1 shuffles rules before pushing, so roughly half of shadow/subnet pairs are reversed and will be missed. This is intentional — it demonstrates the limitation of purely positional detection.

------

## Task 2: Run Full Analysis Including Unused Detection

After Lab 2 traffic has been generated:

```bash
python3 main.py analyze --traditional
```

Expected output adds:

```
Pass A — Behavioral: FortiGate hit-count analysis
  Total lab policies : 100
  Used               : ~68
  Unused (0 hits)    : ~32
```

------

## Task 3: Compare Against Ground Truth

Open both reports side by side:

```bash
cat lab_output/zero_report.json | python3 -m json.tool | grep -A2 '"counts"'
cat lab_output/traditional_report.json | python3 -m json.tool | grep -A2 '"counts"'
```

Fill in the comparison table. Use **groups** for both columns so you compare like with like — divide the zero-report's `counts.duplicate` (policies) by 2 to get duplicate groups, and use `len(shadow_pairs)`, `len(subnet_overlap_pairs)`, `len(service_overlap_groups)` directly from the zero report.

| Issue Type | Ground Truth (zero, groups/pairs) | Detected (traditional, groups/pairs) | Gap |
|------------|-----------------------------------|--------------------------------------|-----|
| Shadow pairs | | | |
| Duplicate groups | | | |
| Subnet-overlap pairs | | | |
| Collapsible svc groups | | | |
| Unused (0 hits, policies) | N/A | | N/A |

> The gap for shadow and subnet-overlap rows demonstrates exactly why AI analysis (Lab 4) is needed to close what traditional scripting misses.

------

> **Next Steps:** Proceed to **Lab 4** to use OpenCode + OpenRouter for interactive AI analysis of the JSON reports generated in this lab. Lab 4 reasons across the full policy set with large language models and closes the detection gap shown in your comparison table.