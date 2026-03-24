# Lab 2 — Traffic Generation & Log Analytics Pipeline

**Estimated Time:** 60–70 minutes

## Goal

Produce realistic traffic, confirm end-to-end logging, and prep data for AI-assisted analysis.

------

## Tasks Overview

- **Presentation** (15–20 min)
- Deploy two Linux hosts (client/server roles). Generate baseline flows (ICMP/HTTP/HTTPS/SSH/SCP) and selected app traffic using Python and open-source tools.
- Verify FortiGate → FortiAnalyzer log ingestion and FortiManager awareness (FAZ datasets/dashboards show policy IDs and traffic summaries).
- Build a quick Policy Hit Count dataset/report in FortiAnalyzer (`policyid`, sessions/bytes) to visualize rule utilization over time.
- Confirm you can query/report via natural language in FAZ (NLQ/voice-to-text for complex queries/reports — where available).

### Feature Validation (Lab 2)

- FAZ custom SQL datasets/reports for policy hit counts are supported.
- FAZ analytics & GenAI assistant are documented by Fortinet (NL query/report assists).

------

# Exercise 1: Generate Baseline Traffic

## Task 1: Deploy Hosts and Generate Baseline Flows

### Step 1 — ICMP (Ping)

```bash
ping 10.0.1.20
```

> 📸 *Screenshot: ICMP Traffic*

------

### Step 2 — HTTP

Install a simple web server on **Host B**:

```bash
python3 -m http.server 8080
```

From **Host A**, browse to Host B:

```bash
curl http://10.0.1.20:8080
```

> 📸 *Screenshot: HTTP Traffic*

------

### Step 3 — HTTPS

Test HTTPS using any available tool or preinstalled service.

> 📸 *Screenshot: HTTPS Traffic*

------

### Step 4 — SSH

Test SSH from Host A to Host B:

```bash
ssh user@10.0.1.20
```

> 📸 *Screenshot: SSH Connection*

------

### Step 5 — SCP

Send an SCP file transfer to generate additional traffic:

```bash
scp testfile.txt user@10.0.1.20:/tmp/
```

> 📸 *Screenshot: SCP Transfer*

------

## Task 2: Generate Application Traffic (Using Python or Tools)

### Step 1 — Python Traffic Generator

Use Python on Host A to generate multiple TCP connections:

```bash
python3 traffic_gen.py
```

> *(Your script will be provided in the final lab package.)*

> 📸 *Screenshot: App Traffic Script*

------

### Step 2 — Open-Source Tools

Use open-source tools such as `iperf3` or `hping3` to create more sessions.

> 📸 *Screenshot: App Traffic Tools*

------

# Exercise 2: Verify Logging and Build Analytics in FortiAnalyzer

## Task 1: Confirm FortiGate → FortiAnalyzer Log Ingestion

1. Log in to **FortiAnalyzer** and open: **Log View → Traffic Logs**

   > 📸 *Screenshot: FAZ Traffic Logs*

2. Check that traffic sessions from Host A → Host B appear with correct policy IDs.

3. Verify the timestamps and byte counts match the traffic you generated.

   > 📸 *Screenshot: FAZ Log Details*

------

## Task 2: Confirm FortiManager Awareness of Traffic

1. On **FortiManager**, go to: **Device Manager → Logs or Summary Widgets**

   > 📸 *Screenshot: FMG Traffic Summary*

2. Confirm that the device shows active traffic and policy usage.

------

# Exercise 3: Build a Policy Hit Count Dataset and Report

## Task 1: Create a Custom SQL Dataset in FortiAnalyzer

1. Go to: **Analytics → Datasets → Create New**

   > 📸 *Screenshot: Create Dataset*

2. Enter a name: **Policy Hit Count Dataset**.

3. Use the following SQL query (already provided in the lab environment):

   > 📸 *Screenshot: SQL Dataset Example*

4. Save the dataset.

------

## Task 2: Build a Report Using the Dataset

1. Go to: **Reports → Create New → Custom Report**

   > 📸 *Screenshot: Create Custom Report*

2. Add a chart that shows:

   - `policyid`
   - `number of sessions`
   - `bytes`

3. Run the report and wait for it to finish.

   > 📸 *Screenshot: Policy Hit Count Report*

------

# Exercise 4: Test Natural Language Query (NLQ)

## Task 1: Ask Questions Using Simple English

1. On FortiAnalyzer, go to: **Analytics → Natural Language Query (NLQ)**

   > 📸 *Screenshot: NLQ Interface*

2. Ask questions like:

   - *"Show the top firewall rules by session count."*
   - *"Which policies had no traffic in the last 10 minutes?"*

   > 📸 *Screenshot: NLQ Example Query*

3. Review the generated dataset or chart.

------

> **Next Steps:** If you want, proceed to **Lab 3**, or merge all labs into a full workshop guide.