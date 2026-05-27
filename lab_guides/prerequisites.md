# Prerequisites

Complete every item in this checklist before starting Lab 1. Missing prerequisites will cause failures mid-lab and are difficult to recover from without disrupting other participants.

---

## 1. Infrastructure — Virtual Machines

The active workshop path (Labs 1–5) requires two VMs: **FortiGate** and **Linux Host A**. **FortiAnalyzer** and **Linux Host B** are optional — only deploy them if you plan to complete the FortiAnalyzer appendix in Lab 1 or the optional Host B connectivity flows in Lab 2. FortiManager is intentionally out of scope.

| Component | Version | Management IP | Notes |
|-----------|---------|---------------|-------|
| **FortiGate** | FortiOS 8.0 | `172.16.0.4` (port3 / mgmt) | port2 = `192.168.1.4` (inside), port1 = `10.10.0.4` (outside) |
| **Linux Host A** | Ubuntu 22.04+ recommended | `192.168.1.100` (inside LAN — eth0) | Required: runs the lab tool, generates traffic, runs OpenCode |
| **FortiAnalyzer** *(optional)* | 8.0 | `172.16.0.5` | Only required if you complete the FortiAnalyzer appendix in Lab 1 |
| **Linux Host B** *(optional)* | Ubuntu 22.04+ recommended | `10.10.0.100` (outside WAN — eth0) | Only required if you run the optional Host B connectivity flows in Lab 2 |

Supported hypervisors: VMware ESXi / Workstation, VirtualBox, KVM/QEMU.

---

## 2. Licenses

The following licenses must be active before the workshop begins. Verify license status in each device's GUI under **System → FortiGuard** or **Dashboard → License**.

| License | Required For | Where to Verify |
|---------|-------------|-----------------|
| FortiGate VM license | All labs | FortiGate GUI → Dashboard |
| FortiAnalyzer VM license *(optional)* | Only for the optional FAZ appendix | FortiAnalyzer GUI → Dashboard |
| **FortiAI Assist** (FAZ) *(optional)* | Only for the optional FAZ NLQ demo in Lab 2 appendix | FortiAnalyzer → System Settings → FortiAI |

> The optional FortiAI Assist FAZ license must be applied **before** the Lab 2 FAZ appendix if you plan to use the Natural Language Query playground. If the license is not active, the FortiAI module will not appear in the FAZ navigation menu.

---

## 3. API Credentials

The following keys must be obtained before Lab 2. FortiGate and FortiAnalyzer tokens are created during Lab 1 Exercise 3 — have the other two ready in advance.

| Credential | Used In | How to Obtain |
|------------|---------|---------------|
| **FortiGate REST API token** | Phase 1, 2, 3, 4 | Created in Lab 1 Exercise 3 |
| **FortiAnalyzer REST API token** *(optional)* | Phase 4 FAZ cleanup only | Created in the optional Lab 1 FAZ appendix |
| **OpenRouter API key** | Phase 3 AI analysis (OpenCode) | [openrouter.ai](https://openrouter.ai) — configure in OpenCode settings |

> The OpenRouter key is configured in OpenCode, not in `config.yaml`. No AI keys are stored in the project config files.

---

## 4. Software on Linux Hosts

Run these checks on **Linux Host A** before Lab 1. Linux Host B is not required for traffic generation — all lab rules are inside→outside only.

### Python

```bash
python3 --version    # Must be 3.10 or higher
pip3 --version
```

### hping3 *(optional)*

`hping3` is only needed for the **optional** connectivity sanity-check flows in Lab 2 Task 3. If you are following the standard path (Linux Host A only), you can skip this.

```bash
hping3 --version
```

If not installed:

```bash
sudo apt update && sudo apt install -y hping3
```

### Lab repository

The lab tool files are pre-installed on Linux Host A at `/home/labadmin/tools`. Set up the Python virtual environment:

```bash
cd /home/labadmin/tools
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
  analyze  Phase 3: Detect policy issues using ground truth and/or...
  cleanup  Phase 4: Delete test-tagged logs from FortiAnalyzer.
  reset    Delete all lab rules AND all lab logs (full reset).
  rules    Phase 1: Generate and push firewall rules to FortiGate.
  traffic  Phase 2: Generate traffic between LinuxA and LinuxB.
```

### Root access

Phase 2 traffic generation requires raw socket access on Linux Host A. Verify `sudo` works:

```bash
sudo python3 -c "import socket; print('raw socket access OK')"
```

---

## 5. Network Connectivity Checks

Verify the following paths are reachable **before** starting Lab 1. All failures must be resolved at the network or firewall level before proceeding.

| From | To | Test |
|------|----|------|
| Workstation | FortiGate GUI | `https://192.168.1.4` loads in browser |
| Linux Host A | FortiGate port2 (inside) | `ping 192.168.1.4` |
| Linux Host A | FortiGate API | `curl -sk https://192.168.1.4/api/v2/cmdb/system/status -H "Authorization: Bearer <token>"` returns JSON *(verify after Lab 1 Exercise 2 — the API token does not exist yet)* |
| Linux Host B | FortiGate port1 (outside) *(optional)* | `ping 10.10.0.4` — only if Host B is deployed |
| Linux Host A | Linux Host B (through FGT) *(optional)* | `ping 10.10.0.100` — only if Host B is deployed |
| Linux Host B | Linux Host A (through FGT) *(optional)* | `ping 192.168.1.100` — only if Host B is deployed |
| Workstation | FortiAnalyzer GUI *(optional)* | `https://172.16.0.5` loads in browser — only if FAZ deployed |
| Linux Host A | FortiAnalyzer API *(optional)* | `curl -sk https://172.16.0.5/jsonrpc -H "Authorization: Bearer <faz-token>"` returns JSON |

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
[ ] Linux Host A: Python 3.10+, repo cloned, pip install done
[ ] (Optional) Linux Host A: hping3 installed (`hping3 --version`) — only needed for Lab 2 Task 3 optional connectivity flows
[ ] Linux Host A: sudo works (`sudo -n true`)
[ ] Linux Host A can ping FortiGate at 192.168.1.4
[ ] OpenRouter API key available (configured in OpenCode)
[ ] config.yaml.example copied to config.yaml (done in Lab 1 Exercise 2, Task 4)
[ ] (Optional) Linux Host B is deployed and Linux Host A can ping it through FortiGate — only for the optional Lab 2 Host B flows
[ ] (Optional) FortiAnalyzer is reachable at https://172.16.0.5 — only if doing the FAZ appendix
[ ] (Optional) FortiAI Assist license is active on FortiAnalyzer — only if doing the FAZ appendix
```
