# Network Topology

The following topology is used across the labs. It includes a FortiGate running FortiOS 8.0, a FortiManager 8.0, a FortiAnalyzer 8.0, and two Linux hosts that generate traffic. One Linux host is connected to the inside network of the FortiGate, and the other is connected to the outside network.

This setup allows you to test policies, analyze logs, and validate AI‑generated changes with real traffic flows.

![Alt text](images/network_topology.png)

------

## Component Summary

| Component                  | Role                              | Key Functions                                                |
| -------------------------- | --------------------------------- | ------------------------------------------------------------ |
| **FortiGate 8.0**          | Main Firewall (Device Under Test) | Hosts policy packages · Generates traffic via inside/outside interfaces · Sends logs to FortiAnalyzer · Managed by FortiManager |
| **FortiAnalyzer 8.0**      | Log & Reporting Engine            | Collects FortiGate logs · Generates policy usage reports · Validates before/after policy changes |
| **FortiManager 8.0**       | Central Policy Management         | Manages policies via ADOMs · Runs FortiAI for script generation & analysis · Supports previews, diff checks, and rollbacks |
| **Linux Host A** (Inside)  | Internal Traffic Generator        | Simulates internal users · Drives policy hit counts · Validates log entries |
| **Linux Host B** (Outside) | External Traffic Generator        | Simulates external systems · Drives policy hit counts · Validates log entries |

## IP Addressing 

| Device                | Interface       | IP Address    | Subnet Mask | Gateway     | Network     |
| --------------------- | --------------- | ------------- | ----------- | ----------- | ----------- |
| **FortiGate 8.0**     | port1 (Inside)  | 192.168.1.1   | /24         | —           | Inside LAN  |
| **FortiGate 8.0**     | port2 (Outside) | 10.0.0.1      | /24         | —           | Outside WAN |
| **FortiGate 8.0**     | mgmt            | 172.16.0.1    | /24         | —           | Management  |
| **FortiAnalyzer 8.0** | mgmt            | 172.16.0.2    | /24         | 172.16.0.1  | Management  |
| **FortiManager 8.0**  | mgmt            | 172.16.0.3    | /24         | 172.16.0.1  | Management  |
| **Linux Host A**      | eth0            | 192.168.1.100 | /24         | 192.168.1.1 | Inside LAN  |
| **Linux Host B**      | eth0            | 10.0.0.100    | /24         | 10.0.0.1    | Outside WAN |