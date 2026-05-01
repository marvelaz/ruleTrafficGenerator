# Lab 5: Multi-Device Policy Consolidation with Policy Blocks and Metadata Variables

In this lab, you will learn how to create shared security policies that work across many FortiGate firewalls. You will use Policy Blocks to build reusable rule sets and metadata variables to make device-specific settings easy to manage.

You will also use FortiAI to help create scripts and objects that can later be added into Policy Blocks.

By the end of this lab, you will be able to standardize firewall policies across multiple devices with much less manual work.

------

## Objectives

- Learn how to add multiple FortiGate devices into FortiManager and prepare them for shared policies.
- Build reusable Policy Blocks and apply metadata variables to customize settings per device.
- Use FortiAI to create starter scripts and objects for faster policy building.

------

## Time to Complete

**Estimated:** 70–75 minutes

------

## Exercise 1: Adding Extra FortiGate Devices into FortiManager

### Task 1 — Add 1–2 FortiGate VMs

1. Log in to FortiManager using your lab credentials.

   > 📸 *Screenshot: FortiManager Login*

2. In the left menu, click **Device Manager**.

   > 📸 *Screenshot: Device Manager*

3. Click **Add Device** → **Add Model Device** or **Add via IP**, depending on your lab.

   > 📸 *Screenshot: Add Device*

4. Enter the device information for the additional FortiGates.

5. When the devices appear, verify they are inside the same ADOM or correct ADOM version.

   > 📸 *Screenshot: ADOM Assignment*

6. Confirm that all devices show a green, healthy connection.

------

## Exercise 2: Creating Reusable Policy Blocks

### Task 1 — Build Standard Policy Blocks

1. Go to **Policy & Objects** → **Policy Blocks**.

   > 📸 *Screenshot: Policy Blocks Menu*

2. Click **Create New Policy Block**.

3. Create the following example blocks:

   - Standard Outbound Internet
   - Inbound VIP + NAT
   - East-West Micro-Segmentation

4. For each block:

   - Add firewall rules
   - Assign standard service and address objects
   - Give each block a clear description

   > 📸 *Screenshot: Creating Policy Block*

5. Save the blocks.

### Task 2 — Add Policy Blocks to Policy Packages

1. Open the policy package for one of your FortiGates.

2. Click **Insert Policy Block**.

   > 📸 *Screenshot: Add Policy Block*

3. Choose one of the blocks you created.

4. Insert it into the correct part of the policy list.

5. Repeat for the other blocks as needed.

------

## Exercise 3: Creating Metadata Variables and Mapping Them to Devices

### Task 1 — Create Metadata Variables

1. In the left menu, select **Policy & Objects** → **Metadata Variables**.

   > 📸 *Screenshot: Metadata Variables Menu*

2. Click **Create New Variable**.

3. Create variables such as:

   - `site_id`
   - `wan_ip`
   - `mgmt_subnet`

   > 📸 *Screenshot: Create Variable*

4. Save your changes.

### Task 2 — Map Variables per Device

1. Click **Per-Device Mapping** inside the Metadata Variables menu.

   > 📸 *Screenshot: Per Device Mapping*

2. Select one variable (for example: `wan_ip`).

3. Enter a unique value for each FortiGate device.

4. Repeat for the other variables.

5. **Optional:** Import mappings using CSV/JSON.

   > 📸 *Screenshot: Import Mappings*

------

## Exercise 4: Using FortiAI to Create Objects and Scripts

### Task 1 — Generate Starter Objects with FortiAI

1. Click the **FortiAI** icon at the top of the screen.

   > 📸 *Screenshot: FortiAI Icon*

2. Type a prompt such as:

   > *"Create address objects for standard internal networks and suggest names."*

3. Review the suggested objects.

   > 📸 *Screenshot: AI Object Suggestions*

4. Next prompt:

   > *"Create VIP templates and IP pools using metadata variables."*

5. Copy or save the generated script for use in Policy Blocks.

------

## Exercise 5: Installing to Multiple FortiGates and Validating

### Task 1 — Install Policies

1. Open the policy package containing your Policy Blocks.

2. Click **Install Wizard**.

   > 📸 *Screenshot: Install Wizard*

3. Select multiple FortiGate targets.

4. Run **Install Preview** to confirm the metadata variables were replaced correctly.

5. Click **Install** to apply the changes.

   > 📸 *Screenshot: Install to Multiple Devices*

### Task 2 — Validate Success

1. Log in to **FortiAnalyzer**.

2. Run a **Policy Hit Count Report** to confirm rules are active.

   > 📸 *Screenshot: FAZ Reports*

3. Confirm that:

   - Policies were installed without errors
   - Variables were replaced with the correct values
   - Each firewall received the right Policy Blocks

------

## Exercise 6: Exporting Templates and Scripts

### Task 1 — Export for Reuse

1. In FortiManager, open **System Settings** → **Export**.

   > 📸 *Screenshot: Export Menu*

2. Export:

   - Policy Blocks
   - Metadata variable mappings
   - AI-generated scripts

3. Save these as your "take-home" templates.