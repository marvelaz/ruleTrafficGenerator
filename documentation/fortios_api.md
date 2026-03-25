To configure an API token on a FortiGate device for use by a Python script to manage firewall rules, follow this procedure based on the management and security principles detailed in the sources:
1. Create a Dedicated Administrator Profile
Before creating the API user, you must define what it is allowed to do.
Navigate to the GUI: Open a web browser and log in to the FortiGate management interface (default is https://192.168.1.99)
.
Access Profiles: Go to System > Admin Profiles
.
Create New Profile: Click Create New to build a profile specifically for your script (e.g., Python_Script_Profile)
.
Assign Permissions: Under Access Control, locate the Firewall area and set it to Read/Write
. This permission is necessary for the script to create, modify, or delete firewall policies (rules)
.
2. Configure the REST API Administrator
Navigate to Administrators: Go to System > Administrators
.
Create API User: Select Create New > REST API Admin. While the specific "REST API Admin" menu is standard for this version of FortiOS, the sources confirm the requirement to enable "access to FortiGate REST API" for external integration
.
Assign the Profile: Select the administrator profile you created in Step 1.
Disable PKI (Optional): Ensure PKI Group is not required unless your script uses certificate-based authentication
.
3. Restrict Access via Trusted Hosts (Security Best Practice)
To prevent unauthorized use of the API token, you must define which machines are allowed to use it.
Configure Trusted Hosts: Within the API user configuration, enable Restrict login to trusted hosts
.
Add IP Addresses: Enter the specific IP address or subnet of the machine where your Python script will run (e.g., 10.0.1.10/32)
.
Warning: Leaving this as 0.0.0.0/0 allows any source IP to attempt access, which is a security risk
.
4. Generate and Secure the API Token
Finalize Creation: After clicking OK to save the new REST API Admin, FortiOS will generate an API Key (Token).
Save the Token: Copy this token immediately and store it securely. The token is displayed only once and cannot be retrieved later; if lost, you must generate a new one.
5. Integration with Python
Once you have the token, your Python script can use it to perform administrative tasks via standard web-based APIs
.
The script should include the token in its HTTPS request headers to authenticate against the FortiGate.
When the script sends a request, FortiGate will validate the token, check the Trusted Hosts to ensure the request is coming from a permitted IP, and then apply the Administrator Profile permissions to allow or deny the rule configuration
.
Note: If your FortiGate is part of a High Availability (HA) cluster, you may need to connect to the primary device to perform these configurations, as secondary members typically do not respond to management traffic unless a dedicated management interface is configured
