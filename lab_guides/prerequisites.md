# Prerequisites

Complete every item in this checklist before starting Lab 1. Missing prerequisites will cause failures mid-lab and are difficult to recover from without disrupting other participants.

---

## 1. Infrastructure — Virtual Machines

All five components must be deployed and powered on before Lab 1 begins.

| Component | Version | Management IP | Notes |
|-----------|---------|---------------|-------|
| **FortiGate** | FortiOS 8.0 | `172.16.0.4` (mgmt) | port1 = `192.168.1.4` (inside), port2 = `10.10.0.4` (outside) |
| **FortiManager** | 8.0 | `172.16.0.6` | Same hypervisor host or reachable via management network |
| **FortiAnalyzer** | 8.0 | `172.16.0.5` | Must have sufficient disk space for log ingestion |
| **Linux Host A** | Ubuntu 22.04+ recommended | `192.168.1.100` | Connected to inside LAN — eth0 |
| **Linux Host B** | Ubuntu 22.04+ recommended | `10.10.0.100` | Connected to outside WAN — eth0 |

Supported hypervisors: VMware ESXi / Workstation, VirtualBox, KVM/QEMU.

---

## 2. Licenses

The following licenses must be active before the workshop begins. Verify license status in each device's GUI under **System → FortiGuard** or **Dashboard → License**.

| License | Required For | Where to Verify |
|---------|-------------|-----------------|
| FortiGate VM license | All labs | FortiGate GUI → Dashboard |
| FortiManager VM license | Labs 1, 3, 4, 5 | FortiManager GUI → Dashboard |
| FortiAnalyzer VM license | Labs 1, 2, 3, 4 | FortiAnalyzer GUI → Dashboard |
| **FortiAI Assist** (FMG) | Labs 3 and 4 | FortiManager → System Settings → FortiAI |
| **FortiAI Assist** (FAZ) | Labs 2 and 3 | FortiAnalyzer → System Settings → FortiAI |

> FortiAI Assist licenses must be applied and validated **before** Lab 1 Exercise 2. If the license is not active, the FortiAI module will not appear in the navigation menu.

---

## 3. API Credentials

The following keys must be obtained before Lab 2. FortiGate and FortiAnalyzer tokens are created during Lab 1 Exercise 3 — have the other two ready in advance.

| Credential | Used In | How to Obtain |
|------------|---------|---------------|
| **FortiGate REST API token** | Phase 1, 2, 3 | Created in Lab 1 Exercise 3 |
| **FortiAnalyzer REST API token** | Phase 3 | Created in Lab 1 Exercise 3 |
| **OpenAI API key** (`sk-...`) | Phase 3 AI analysis | [platform.openai.com](https://platform.openai.com) — requires GPT-4o access |
| **Anthropic API key** (`sk-ant-...`) | Phase 3 AI analysis | [console.anthropic.com](https://console.anthropic.com) |

> OpenAI and Anthropic keys must have sufficient quota for Phase 3. Each analysis run sends the full rule set as JSON — budget for approximately 8,000–12,000 tokens per model call depending on rule count.

---

## 4. Software on Linux Hosts

Run these checks on **both** Linux Host A and Linux Host B before Lab 1.

### Python

```bash
python3 --version    # Must be 3.10 or higher
pip3 --version
```

### hping3

```bash
hping3 --version
```

If not installed:

```bash
sudo apt update && sudo apt install -y hping3
```

### Lab repository

```bash
git clone <repo-url> ~/ruleTrafficGenerator
cd ~/ruleTrafficGenerator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify installation:

```bash
python3 main.py --help
```

Expected output:

```
Usage: main.py [OPTIONS] COMMAND [ARGS]...

  FortiGate Rule Optimization Lab — Orchestrator

Options:
  --config TEXT  Path to config.yaml  [default: config.yaml]
  --help         Show this message and exit.

Commands:
  all      Run phases 1 -> 2 -> 3 in sequence.
  analyze  Phase 3: Analyze hit counts via FortiGate, FortiAnalyzer...
  cleanup  Phase 4: Delete test-tagged logs from FortiGate and...
  reset    Delete all lab rules AND all lab logs (full reset).
  rules    Phase 1: Generate and push firewall rules to FortiGate.
  traffic  Phase 2: Generate traffic between linux1 and linux2.
```

### Root access

Phase 2 traffic generation requires raw socket access. Verify sudo works on both hosts:

```bash
sudo python3 -c "import socket; print('raw socket access OK')"
```

---

## 5. Network Connectivity Checks

Verify the following paths are reachable **before** starting Lab 1. All failures must be resolved at the network or firewall level before proceeding.

| From | To | Test |
|------|----|------|
| Workstation | FortiGate GUI | `https://192.168.1.4` loads in browser |
| Workstation | FortiManager GUI | `https://172.16.0.6` loads in browser |
| Workstation | FortiAnalyzer GUI | `https://172.16.0.5` loads in browser |
| Linux Host A | FortiGate port1 | `ping 192.168.1.4` |
| Linux Host B | FortiGate port2 | `ping 10.10.0.4` |
| Linux Host A | Linux Host B (through FGT) | `ping 10.10.0.100` |
| Linux Host B | Linux Host A (through FGT) | `ping 192.168.1.100` |
| Linux Host A | FortiGate API | `curl -sk https://192.168.1.4/api/v2/cmdb/system/status -H "Authorization: Bearer <token>"` returns JSON |

---

## 6. Knowledge Prerequisites

Participants should be comfortable with the following before attending.

| Topic | Level Required |
|-------|---------------|
| FortiGate GUI navigation | Basic — creating policies, viewing logs |
| FortiOS CLI | Basic — `config` / `edit` / `set` / `end` |
| Linux CLI | Basic — running commands, editing files with `vi` or `nano`, using `sudo` |
| YAML syntax | Basic — reading and editing key-value config files |
| REST APIs | Awareness — understanding what a token is and how it authenticates a request |

No Python development experience is required. Students only run the tool, not write it.

---

## 7. Pre-Lab Verification Checklist

Use this checklist at the start of each session to confirm readiness.

```
[ ] FortiGate is reachable at https://192.168.1.4
[ ] FortiManager is reachable at https://172.16.0.6
[ ] FortiAnalyzer is reachable at https://172.16.0.5
[ ] FortiAI Assist license is active on FortiManager
[ ] FortiAI Assist license is active on FortiAnalyzer
[ ] Linux Host A: Python 3.10+, hping3, repo cloned, pip install done
[ ] Linux Host B: Python 3.10+, hping3, repo cloned, pip install done
[ ] Linux Host A can ping Linux Host B through FortiGate
[ ] Linux Host B can ping Linux Host A through FortiGate
[ ] OpenAI API key available
[ ] Anthropic API key available
[ ] config.yaml.example copied to config.yaml (done in Lab 1 Exercise 3)
```
