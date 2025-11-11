CVE Flaw Update Script
This script automates the process of updating CVE flaws in OSIDB by:
Extracting CVE IDs from a text file
Adding components to each CVE (if not already present)
Assigning ownership (if not already assigned)
Prerequisites
Python 3 with osidb_bindings package installed
Access to OSIDB (https://osidb.prodsec.redhat.com/)
Proper authentication credentials configured for OSIDB
Installation
Make the script executable:
chmod +x update_cve_flaws.sh

Usage
./update_cve_flaws.sh <input_file> <component> <owner>

Arguments:
input_file: Path to the text file containing CVE data
component: Component name to assign to CVEs (e.g., 'kernel', 'intel_wifi')
owner: Owner username (e.g., 'rh-ee-username')
Example:
./update_cve_flaws.sh cves.txt intel_wifi rh-ee-username

Input File Format
The script expects a text file with CVE data in any format, as long as CVE IDs follow the pattern CVE-YYYY-XXXXX. Example:
CVE-2025-35971	IMPORTANT	2025-11-11 17:02	From CVEorg collector	NEW	
CVE-2025-35967	IMPORTANT	2025-11-11 17:02	From CVEorg collector	NEW	
CVE-2025-35963	IMPORTANT	2025-11-11 17:05	From CVEorg collector	NEW	
CVE-2025-20010	MODERATE	2025-11-11 17:03	From CVEorg collector	NEW

The script will automatically extract all unique CVE IDs from the file, regardless of format.
How It Works
1. Extract CVE IDs
The script parses the input file using regex (CVE-[0-9]{4}-[0-9]+) and extracts all unique CVE IDs into an array.
2. Create OSIDB Session
Establishes a connection to OSIDB using osidb_bindings.
3. Process Each CVE
For each CVE ID, the script:
a. Component Update (First)
Retrieves the flaw data from OSIDB
Checks if flaw_data.components is empty ([''] or empty list)
If empty:
Sets flaw_data.components = [component]
Updates the flaw in OSIDB
Re-retrieves the flaw data to ensure fresh state
Logs: [+] CVE-XXXX-XXXXX: Component updated to 'component_name'
If already set:
Skips component update
Logs: [i] CVE-XXXX-XXXXX: Component already set (['existing_component'])
b. Owner Assignment (Second)
Checks if flaw_data.owner is empty ('' or None)
If empty:
Sets flaw_data.owner = owner
Updates the flaw in OSIDB
Logs: [+] CVE-XXXX-XXXXX: Owner updated to 'username'
If already assigned:
Skips owner update
Logs: [i] CVE-XXXX-XXXXX: Owner already assigned (existing_owner)
c. Error Handling
Catches requests.exceptions.HTTPError for update failures
Catches general Exception for any other errors
Prints full traceback for debugging
Continues processing remaining CVEs even if one fails
4. Summary Report
After processing all CVEs, displays:
Total CVEs found and processed
Number of successful updates
Number of failures
Output Example
[*] Processing CVEs from: cves.txt
[*] Component: intel_wifi
[*] Owner: rh-ee-username

[*] Found 42 unique CVE IDs

----------------------------------------
[*] Processing: CVE-2025-20010
[+] CVE-2025-20010: Component updated to 'intel_wifi'
[+] CVE-2025-20010: Owner updated to 'rh-ee-username'
[✓] CVE-2025-20010: Successfully updated

----------------------------------------
[*] Processing: CVE-2025-20011
[i] CVE-2025-20011: Component already set (['intel_wifi'])
[i] CVE-2025-20011: Owner already assigned (rh-ee-other)
[✓] CVE-2025-20011: No updates needed

----------------------------------------
[*] Processing: CVE-2025-20012
[+] CVE-2025-20012: Component updated to 'intel_wifi'
[!] CVE-2025-20012: Failed to update owner: 403 Forbidden
[!] Failed with exit code: 1

========================================
SUMMARY
========================================
Total CVEs processed: 42
Successfully updated: 40
Failed: 2
========================================
[✓] Successfully updated 40 CVE flaw(s)!
[!] Warning: 2 CVE(s) failed to update

Important Notes
Update Order
The script updates in this specific order to satisfy OSIDB constraints:
Component first - Required before ownership can be assigned
Flaw data refresh - Re-retrieves flaw after component update
Owner second - Assigned only after component is set
Non-Destructive Updates
Never overwrites existing values
Only updates empty/unset fields
Skips CVEs that already have components or owners assigned
Safe to run multiple times on the same file
Error Handling
Each CVE is processed independently
Failures don't stop the entire batch
Detailed error messages for debugging
Exit code 0 if all succeed, exit code 0 even with partial failures (summary shows counts)
Temporary Files
Creates a temporary Python script in /tmp/ for OSIDB operations
Automatically cleaned up after execution
Uses mktemp for secure temporary file creation
Troubleshooting
Authentication Issues
Problem: 401 Unauthorized or 403 Forbidden errors
Solution: Ensure your OSIDB credentials are properly configured. Check:
Environment variables
Kerberos ticket (klist)
VPN connection
Module Import Errors
Problem: ModuleNotFoundError: No module named 'osidb_bindings'
Solution: Install the package:
pip install osidb-bindings

Permission Denied
Problem: bash: ./update_cve_flaws.sh: Permission denied
Solution: Make the script executable:
chmod +x update_cve_flaws.sh

HTTPError on Update
Problem: requests.exceptions.HTTPError: 400 Bad Request
Possible Causes:
Invalid component name
Invalid owner username
Flaw in invalid state for updates (e.g., already DONE or REJECTED)
Debug Steps:
Check the specific error message in the output
Verify the CVE exists in OSIDB
Verify component is valid
Check flaw state (must be NEW, TRIAGE, PRE_SECONDARY_ASSESSMENT, etc.)
Advanced Usage
Processing Multiple Files
for file in cve_batch_*.txt; do
    ./update_cve_flaws.sh "$file" kernel rh-ee-username
done

Logging Output
To save output to a log file:
./update_cve_flaws.sh cves.txt intel_wifi rh-ee-username 2>&1 | tee update_log.txt
