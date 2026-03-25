# Lab 2 — Traffic Generation & Log Analytics Pipeline

**Estimated Time:** 60–70 minutes

## Goal

Use the lab automation tool to generate realistic bidirectional traffic across FortiGate, confirm end-to-end logging into FortiAnalyzer, and build analytics that show policy hit counts. This data is the foundation for the AI-assisted analysis in Lab 3.

## Design Intent

The traffic generator is deliberately calibrated to match **60–75%** of configured firewall rules. The remaining **25–40%** of rules will have zero hit counts. Those zero-hit rules are the candidates for unused-rule detection — do not try to fix them; they are intentional.

All rules and log entries created by the tool are tagged `LAB-TEST-2025`. This tag makes every log entry filterable and ensures cleanup operations only affect lab-generated data.

------

## Tasks Overview

- Set up IP aliases on both Linux hosts.
- Generate baseline flows (ICMP, HTTP, HTTPS, SSH, DNS) and directed application traffic using the lab tool.
- Verify FortiGate → FortiAnalyzer log ingestion and confirm policy IDs appear in traffic logs.
- Build a Policy Hit Count dataset and report in FortiAnalyzer.
- Test natural language queries (NLQ) against the collected log data.

------

# Exercise 1: Prepare Linux Hosts for Traffic Generation

## Task 1: Add IP Aliases to Both Linux Hosts

Both Linux hosts need virtual IP aliases on their primary interface before traffic generation begins. These aliases simulate multiple distinct source and destination hosts, making traffic patterns appear realistic rather than single-host.

Run the following command **on Linux Host A** (inside, `192.168.1.100`) as root:

```bash
sudo python3 main.py traffic --setup-aliases
```

Expected output:

```
Added alias 192.168.1.101 to eth0
Added alias 192.168.1.102 to eth0
...
Added alias 192.168.1.110 to eth0
Aliases configured successfully.
```

Repeat **on Linux Host B** (outside, `10.10.0.100`) as root:

```bash
sudo python3 main.py traffic --setup-aliases
```

Expected output:

```
Added alias 10.10.0.101 to eth0
Added alias 10.10.0.102 to eth0
...
Added alias 10.10.0.110 to eth0
Aliases configured successfully.
```

> Aliases persist until removed with `--remove-aliases` or until the host is rebooted. You only need to run this once per host per session.

------

# Exercise 2: Generate Baseline Traffic

## Task 1: Generate Bidirectional Traffic Using the Lab Tool

The primary traffic generation method uses the lab tool (`main.py`). It drives Scapy for packet crafting and hping3 for TCP flag variation, covering all traffic types required by the scenario.

### Step 1 — Inside → Outside (run on Linux Host A)

```bash
sudo python3 main.py traffic --direction in2out
```

This sends traffic from Linux Host A (`192.168.1.100` and aliases `.101–.110`) toward Linux Host B (`10.10.0.100` and aliases `.101–.110`) through FortiGate port1 → port2.

### Step 2 — Outside → Inside (run on Linux Host B)

```bash
sudo python3 main.py traffic --direction out2in
```

This sends traffic from Linux Host B (`10.10.0.100` and aliases `.101–.110`) toward Linux Host A through FortiGate port2 → port1.

### Step 3 — Bidirectional with session limit (optional, single host)

If your environment allows both directions from one host:

```bash
sudo python3 main.py traffic --direction both --sessions 200
```

> Stop traffic at any time with **Ctrl+C**. No daemon is running — traffic stops immediately.

------

## Task 2: Generate Baseline Flows Manually (Supplementary)

These manual flows are useful for verifying that basic connectivity and logging work before running the full tool.

### Step 1 — ICMP

From Linux Host A, ping Linux Host B:

```bash
ping -c 4 10.10.0.100
```

Expected output:

```
PING 10.10.0.100 (10.10.0.100) 56(84) bytes of data.
64 bytes from 10.10.0.100: icmp_seq=1 ttl=63 time=0.8 ms
64 bytes from 10.10.0.100: icmp_seq=2 ttl=63 time=0.7 ms
...
4 packets transmitted, 4 received, 0% packet loss
```

------

### Step 2 — HTTP

Install a simple web server on **Linux Host B**:

```bash
python3 -m http.server 8080
```

From **Linux Host A**, send an HTTP request:

```bash
curl -v http://10.10.0.100:8080
```

Expected output (truncated):

```
* Connected to 10.10.0.100 (10.10.0.100) port 8080
> GET / HTTP/1.1
> Host: 10.10.0.100:8080
...
< HTTP/1.0 200 OK
```

------

### Step 3 — HTTPS

Test HTTPS from Linux Host A to any HTTPS service reachable through FortiGate:

```bash
curl -k -v https://10.10.0.100
```

------

### Step 4 — SSH

Test SSH from Linux Host A to Linux Host B:

```bash
ssh user@10.10.0.100
```

------

### Step 5 — SCP

Send a file via SCP to generate an additional traffic session:

```bash
dd if=/dev/urandom bs=1K count=512 | ssh user@10.10.0.100 "cat > /tmp/testfile.bin"
```

------

### Step 6 — DNS (UDP 53)

Generate DNS queries from Linux Host A:

```bash
for i in $(seq 1 10); do
  dig @10.10.0.100 test$i.lab.internal +short
done
```

> DNS traffic (UDP 53 and TCP 53) is one of the traffic types defined in the scenario. These queries exercise DNS-specific rules in the policy set.

------

## Task 3: Generate Application Traffic with hping3

Use hping3 to generate TCP sessions with varied flags and ports, supplementing Scapy sessions with additional 5-tuple diversity:

```bash
# TCP SYN to port 443
hping3 -S -p 443 -c 10 10.10.0.100

# TCP SYN to port 8080
hping3 -S -p 8080 -c 10 10.10.0.100

# TCP SYN to port 3306
hping3 -S -p 3306 -c 5 10.10.0.100
```

------

# Exercise 3: Verify Logging and Build Analytics in FortiAnalyzer

## Task 1: Confirm FortiGate → FortiAnalyzer Log Ingestion

1. Log in to **FortiAnalyzer** at `https://172.16.0.2`.

2. Open: **Log View → Traffic Logs**

   > 📸 *Screenshot: FAZ Traffic Logs*

3. In the search/filter bar, filter by the lab tag:

   ```
   comment LIKE '%LAB-TEST-2025%'
   ```

4. Confirm that traffic sessions from Linux Host A → Linux Host B appear with:
   - Correct source and destination IPs (including alias IPs)
   - Correct policy IDs matching rules generated in Lab 2
   - Timestamps and byte counts consistent with the traffic you generated

   > 📸 *Screenshot: FAZ Log Details*

5. Note that **not all policy IDs appear** — 25–40% of rules are intentionally unmatched. This is expected behavior, not a misconfiguration.

------

## Task 2: Confirm FortiManager Awareness of Traffic

1. On **FortiManager**, go to: **Device Manager → Logs or Summary Widgets**

   > 📸 *Screenshot: FMG Traffic Summary*

2. Confirm that the device shows active traffic and that policy IDs are visible in the summary widgets.

------

# Exercise 4: Build a Policy Hit Count Dataset and Report

## Task 1: Create a Custom SQL Dataset in FortiAnalyzer

1. Go to: **Analytics → Datasets → Create New**

   > 📸 *Screenshot: Create Dataset*

2. Enter the name: **Policy Hit Count — LAB-TEST-2025**

3. Enter the following SQL query:

   ```sql
   SELECT
       policyid,
       count(*)          AS sessions,
       sum(sentbyte)     AS sent_bytes,
       sum(rcvdbyte)     AS rcvd_bytes
   FROM $log-traffic
   WHERE logtype = 'traffic'
     AND comment LIKE '%LAB-TEST-2025%'
   GROUP BY policyid
   ORDER BY sessions DESC
   ```

   > This query aggregates all traffic log entries tagged with `LAB-TEST-2025` by policy ID, showing session counts and byte totals per rule. Policy IDs that do not appear in the results have zero hits.

4. Click **Save**.

------

## Task 2: Build a Report Using the Dataset

1. Go to: **Reports → Create New → Custom Report**

   > 📸 *Screenshot: Create Custom Report*

2. Add a chart with the following columns from the dataset:

   - `policyid`
   - `sessions`
   - `sent_bytes`
   - `rcvd_bytes`

3. Run the report and wait for it to complete.

   > 📸 *Screenshot: Policy Hit Count Report*

4. Export the report as PDF or CSV for use in Lab 3 comparisons.

------

# Exercise 5: Test Natural Language Query (NLQ)

## Task 1: Ask Questions Using Plain English

1. On FortiAnalyzer, go to: **Analytics → Natural Language Query (NLQ)**

   > 📸 *Screenshot: NLQ Interface*

2. Try the following queries:

   ```
   Show the top firewall rules by session count.
   ```

   ```
   Which policies had no traffic in the last 30 minutes?
   ```

   ```
   Show me traffic volume by source IP for the last hour.
   ```

   > 📸 *Screenshot: NLQ Example Query*

3. For each query, review:
   - The generated dataset or chart
   - Whether the policy IDs returned match your expectations from the hit count report

------

> **Next Steps:** Proceed to **Lab 3** to use FortiManager Policy Check and FortiAI to identify unused, shadowed, and conflicting rules using the hit count data collected in this lab.
