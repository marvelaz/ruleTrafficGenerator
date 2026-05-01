# Lab 4: Natural Language to Config — Using Script Assistant with Staging, Diff, and Rollback

In this lab, you will learn how to use natural language (simple English commands) to create firewall cleanup scripts using FortiAI's Script Assistant. You will run these scripts safely inside a staging ADOM or a cloned policy package. Then you will preview the changes, install them on a test FortiGate, check the results in FortiAnalyzer, and practice rolling back if something goes wrong.

This lab teaches you how real administrators use AI to make policy changes faster and safer.

------

## Objectives

- Create firewall cleanup scripts using plain English commands with FortiAI Script Assistant.
- Test changes safely using a staging ADOM, Install Preview, and configuration diff tools.
- Validate results and use rollback features if changes need to be undone.

------

## Time to Complete

**Estimated:** 70–75 minutes

------

## Exercise 1: Using Script Assistant to Generate Cleanup Scripts

### Task 1 — Open FortiAI and Ask for Script Creation

1. Log in to FortiManager with your lab credentials.

   > 📸 *Screenshot: FortiManager Login*

2. Click the **FortiAI** icon in the top bar.

   > 📸 *Screenshot: FortiAI Icon*

3. In the prompt box, type the following command:

   ```
   Identify policies with 0 hits in 30 days; disable them and tag as 'candidate remove'.
   ```

4. Wait for FortiAI to generate a cleanup script.

   > 📸 *Screenshot: Script Assistant Result*

5. Next, type the second command:

   ```
   Merge duplicate address objects with identical CIDRs; update references.
   ```

6. Review the generated script and verify:

   - Policies with zero hits are disabled
   - Tags are correctly added
   - Address objects are merged and references updated

7. Save or copy the script for use in the next exercise.

------

## Exercise 2: Running the Script in a Staging ADOM or Clone

### Task 1 — Prepare a Safe Workspace

1. In the left menu, go to **Administration → ADOMs**.

   > 📸 *Screenshot: ADOM List*

2. If your lab requires a **staging ADOM**:

   - Select the Staging ADOM
   - Open the policy package inside it

3. If your lab uses a **cloned policy package**:

   - In **Policy & Objects**, right-click the original policy package
   - Click **Clone**
   - Name it `lab4-staging`

   > 📸 *Screenshot: Clone Policy Package*

### Task 2 — Run the Script

1. Open the staging policy package.

2. Click **Scripts → Create New**.

   > 📸 *Screenshot: Script Window*

3. Paste the Script Assistant output into the script editor.

4. Click **Run Script** (on the staging ADOM only).

5. Wait for the confirmation message.

   > 📸 *Screenshot: Script Execution*

------

## Exercise 3: Using Install Preview and Diff Tools

### Task 1 — Preview the Changes

1. In the policy package toolbar, click **Install Wizard**.

   > 📸 *Screenshot: Install Wizard*

2. Select the test FortiGate as the target device.

3. Before installing, click **Install Preview**.

4. Review the differences:

   - Disabled rules
   - Tags added
   - Address objects merged

   > 📸 *Screenshot: Config Diff*

5. Confirm that only the expected changes appear.

### Task 2 — Install the Policy

1. If everything looks correct, click **Install**.

2. Wait for the job to finish inside **Task Monitor**.

   > 📸 *Screenshot: Task Monitor*

------

## Exercise 4: Validate the Results Using FortiAnalyzer

### Task 1 — Compare Before and After Behavior

1. Log in to **FortiAnalyzer**.

2. Go to **Reports → FortiGate Reports**.

   > 📸 *Screenshot: FAZ Reports*

3. Run the following:

   - Policy Hit Count Report (Before)
   - Policy Hit Count Report (After)

4. Compare:

   - Previously unused rules should now be disabled
   - Address objects should appear merged
   - No new errors should appear

5. Document any differences you see.

------

## Exercise 5: Rollback Using FortiManager Versioning

### Task 1 — Practice Rollback

1. In FortiManager, go to the **Revision History** or **Versioning** panel for the policy package.

   > 📸 *Screenshot: Revision History*

2. Click **Compare** to view the diff between:

   - Version before script
   - Version after script

3. If you need to revert:

   - Select the previous version
   - Click **Restore**

   > 📸 *Screenshot: Rollback*

4. Run an **Install Preview** again to confirm changes were undone.