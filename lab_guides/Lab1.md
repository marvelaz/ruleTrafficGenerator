# Lab 1: Base Deployment & Security Fabric Registration

## Lab Description

In this lab, you will deploy the base Fortinet components needed for the rest of the workshop. You will set up a FortiGate VM, FortiManager, and FortiAnalyzer, and connect them so they can share information. You will also enable the FortiAI Assist feature so later labs can use AI-driven policy optimization.

By the end of this lab, all devices will be online, registered, and exchanging telemetry across the Security Fabric.

## Objectives

- Set up FortiGate, FortiManager, and FortiAnalyzer with basic networking.
- Register FortiGate to FortiManager and join all devices to the Security Fabric.
- Enable FortiAI Assist on FortiManager and FortiAnalyzer.

## Time to Complete

Estimated: **60–70 minutes**

---

# Exercise 1: Deploy Core Components and Verify Connectivity

## Task 1: Deploy the FortiGate VM

1. Deploy the FortiGate VM using your preferred hypervisor (VMware/VirtualBox/KVM).

   ![Screenshot: Deploying FortiGate VM](screenshots/deploy-fgt.png)

2. Open the console.

   ![Screenshot: FortiGate Console Boot](screenshots/fgt-console-boot.png)

3. Log in using the default credentials:
   - **Username:** `admin`
   - **Password:** *(leave blank, press Enter)*

4. Set a new admin password when prompted.

5. Configure basic networking by assigning an IP to port1 (management):
```
   config system interface
       edit port1
           set ip 192.168.1.1/24
           set allowaccess ping https ssh
       next
   end
```

6. From your workstation, open a browser and navigate to `https://192.168.1.1`.

   ![Screenshot: FortiGate GUI Login](screenshots/fgt-gui-login.png)

---

## Task 2: Deploy FortiManager and FortiAnalyzer

1. Deploy the **FortiManager** VM and **FortiAnalyzer** VM.

   ![Screenshot: Deploying FMG/FAZ](screenshots/deploy-fmg-faz.png)

2. Assign IP addresses to both:
   - FMG: `172.16.0.3` (management network)
   - FAZ: `172.16.0.2` (management network)

3. Log in to each GUI and complete the initial setup wizards.

   ![Screenshot: FMG Setup Wizard](screenshots/fmg-setup-wizard.png)

   ![Screenshot: FAZ Setup Wizard](screenshots/faz-setup-wizard.png)

---

## Task 3: Add FortiGate to FortiManager (FMG)

1. In FortiManager, go to **Device Manager → Add Device**.

   ![Screenshot: Add Device in FMG](screenshots/fmg-add-device.png)

2. Choose **Add Device Manually**.

3. Enter the FortiGate's IP address: `192.168.1.1`.

4. Select the correct **ADOM**.
   > Make sure the ADOM matches the FortiGate firmware version and branch.

5. Accept the authorization request on FortiGate if required.

   ![Screenshot: FGT Authorize FMG](screenshots/fgt-authorize-fmg.png)

6. Verify that FMG → FGT connectivity shows **green/up**.

   ![Screenshot: FMG Connectivity Green](screenshots/fmg-connectivity-green.png)

---

## Task 4: Register Devices to the Security Fabric

1. On FortiGate, go to **Security Fabric → Settings**.

2. Enable the Security Fabric and set FortiAnalyzer as a log destination.

   ![Screenshot: Security Fabric Setup](screenshots/fgt-security-fabric-setup.png)

3. Enter the FAZ IP (`172.16.0.2`) as the log forwarding target.

4. On FortiAnalyzer, verify that logs are received by going to **Log View** and confirming events from the FortiGate.

   ![Screenshot: FAZ Receiving Logs](screenshots/faz-receiving-logs.png)

---

# Exercise 2: Enable and Validate FortiAI Assist

## Task 1: Enable FortiAI Assist Licenses

1. On **FortiManager**, go to **System Settings → FortiAI Assist License**.

   ![Screenshot: FMG AI License](screenshots/fmg-ai-license.png)

2. Enter and apply your FortiAI license key.

3. Repeat these steps on **FortiAnalyzer**.

   ![Screenshot: FAZ AI License](screenshots/faz-ai-license.png)

---

## Task 2: Verify FortiAI Module Visibility

1. On FortiManager, look for the **FortiAI** or **FortiAI Assist** icon in the left navigation menu.

   ![Screenshot: FMG FortiAI Module](screenshots/fmg-forti-ai-module.png)

2. Confirm that the admin account used for this lab has access rights to the module.

3. On FortiAnalyzer, repeat the verification steps.

   ![Screenshot: FAZ FortiAI Module](screenshots/faz-forti-ai-module.png)

---

## Task 3: Validate Overall Fabric and AI Readiness

1. Go to **Security Fabric → Fabric Connectors** on FortiGate and confirm:
   - FMG is connected
   - FAZ is connected
   - Logging is active
   - Fabric Root displays correctly

   ![Screenshot: Fabric Connections](screenshots/fgt-fabric-connections.png)

2. On FortiManager, run a device status check:
   - Go to **Device Manager**
   - Select the FortiGate
   - Click **Status → Check**

   ![Screenshot: FMG Device Status Check](screenshots/fmg-device-status-check.png)

3. Ensure no communication errors appear before continuing to Lab 2.

---

# Exercise 3: Create REST API Tokens for Lab Automation

## Task 1: Create a Dedicated Administrator Profile on FortiGate

Before creating the API user, define what it is allowed to do.

1. Log in to the FortiGate GUI at `https://192.168.1.1`.

   ![Screenshot: FortiGate GUI Login](screenshots/fgt-gui-login.png)

2. Go to **System → Admin Profiles**.

   ![Screenshot: Admin Profiles](screenshots/fgt-admin-profiles.png)

3. Click **Create New** to build a profile specifically for the lab script. Name it `Lab_API_Profile`.

4. Under **Access Control**, locate the **Firewall** area and set it to **Read/Write**.

   > This permission is required for the script to create, modify, and delete firewall policies.

   ![Screenshot: Admin Profile Permissions](screenshots/fgt-admin-profile-permissions.png)

5. Click **OK** to save the profile.

---

## Task 2: Create the REST API Administrator on FortiGate

1. Go to **System → Administrators**.

   ![Screenshot: Administrators](screenshots/fgt-administrators.png)

2. Click **Create New → REST API Admin**.

   ![Screenshot: Create REST API Admin](screenshots/fgt-create-api-admin.png)

3. Assign the profile created in Task 1: select `Lab_API_Profile`.

4. Ensure **PKI Group** is not required (leave it disabled unless your environment uses certificate-based authentication).

---

## Task 3: Restrict Access via Trusted Hosts

1. Within the REST API Admin configuration, enable **Restrict login to trusted hosts**.

   ![Screenshot: Trusted Hosts](screenshots/fgt-trusted-hosts.png)

2. Enter the IP address or subnet of the machine where the lab Python script will run (e.g., `192.168.1.100/32` for Linux Host A).

   > **Security note:** Do not leave this as `0.0.0.0/0`. Restricting to a known source IP prevents unauthorized use of the token.

3. Click **OK** to save.

---

## Task 4: Generate and Save the FortiGate API Token

1. After clicking **OK**, FortiOS displays the generated API token.

   ![Screenshot: API Token Generated](screenshots/fgt-api-token.png)

2. **Copy this token immediately and store it securely.** The token is displayed only once and cannot be retrieved later. If lost, you must generate a new one.

3. Keep the token available — you will paste it into `config.yaml` in Task 6.

---

## Task 5: Create the REST API Token on FortiAnalyzer

1. Log in to the **FortiAnalyzer** GUI at `https://172.16.0.2`.

   ![Screenshot: FortiAnalyzer Login](screenshots/faz-gui-login.png)

2. Go to **System Settings → Administrators**.

   ![Screenshot: FAZ Administrators](screenshots/faz-administrators.png)

3. Click **Create New → REST API Admin**.

4. Assign appropriate read permissions for log and report access.

5. Click **OK**. Copy and save the generated token immediately.

   ![Screenshot: FAZ API Token](screenshots/faz-api-token.png)

---

## Task 6: Configure the Lab Tool

1. On Linux Host A, navigate to the lab directory:

```bash
cd ~/ruleTrafficGenerator
```

2. Copy the example config file:

```bash
cp config.yaml.example config.yaml
```

3. Open `config.yaml` in a text editor and fill in the following values:

   - `fortigate.host` — set to `192.168.1.1`
   - `fortigate.api_token` — paste the token generated in Task 4
   - `fortianalyzer.host` — set to `172.16.0.2`
   - `fortianalyzer.api_token` — paste the token generated in Task 5

4. Save the file.

5. Install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

6. Verify connectivity by running a dry-run of Phase 1:

```bash
python3 main.py rules --count 10 --dry-run
```

   > A successful dry-run prints generated rule definitions without pushing anything to FortiGate. No errors should appear.

   ![Screenshot: Dry Run Output](screenshots/cli-dry-run.png)