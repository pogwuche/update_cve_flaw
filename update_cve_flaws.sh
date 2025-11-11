#!/bin/bash

# Script to update CVE flaws with components and ownership
# Usage: ./update_cve_flaws.sh <input_file> <component> <owner>

# Check if required arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file> <component> <owner>"
    echo "Example: $0 cves.txt 'kernel' 'rh-ee-pogwuche'"
    exit 1
fi

INPUT_FILE="$1"
COMPONENT="$2"
OWNER="$3"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "[!] Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

echo "[*] Processing CVEs from: $INPUT_FILE"
echo "[*] Component: $COMPONENT"
echo "[*] Owner: $OWNER"
echo ""

# Extract CVE IDs from the input file into an array
mapfile -t CVE_ARRAY < <(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$INPUT_FILE" | sort -u)

# Count total CVEs
TOTAL_CVES=${#CVE_ARRAY[@]}
echo "[*] Found $TOTAL_CVES unique CVE IDs"
echo ""

# Create a temporary Python script
PYTHON_SCRIPT=$(mktemp /tmp/osidb_update.XXXXXX.py)

cat > "$PYTHON_SCRIPT" << 'PYTHON_EOF'
#!/usr/bin/env python3

import sys
import osidb_bindings
import requests

def main():
    if len(sys.argv) != 4:
        print("Usage: script.py <component> <owner> <cve_id>")
        sys.exit(1)
    
    component = sys.argv[1]
    owner = sys.argv[2]
    cve_id = sys.argv[3]
    
    try:
        # Create OSIDB session
        OSIDB_SESSION = osidb_bindings.new_session(
            osidb_server_uri='https://osidb.prodsec.redhat.com/'
        )
        
        # Retrieve flaw data
        flaw_data = OSIDB_SESSION.flaws.retrieve(id=cve_id)
        
        component_updated = False
        owner_updated = False
        
        # Update component if empty
        if flaw_data.components == [''] or not flaw_data.components:
            flaw_data.components = [component]
            try:
                OSIDB_SESSION.flaws.update(flaw_data.uuid, form_data=flaw_data.to_dict())
                component_updated = True
                print(f"[+] {cve_id}: Component updated to '{component}'")
                # Re-retrieve flaw data after update
                flaw_data = OSIDB_SESSION.flaws.retrieve(id=cve_id)
            except requests.exceptions.HTTPError as e:
                print(f"[!] {cve_id}: Failed to update component: {e}")
                sys.exit(1)
        else:
            print(f"[i] {cve_id}: Component already set ({flaw_data.components})")
        
        # Update owner if empty
        if flaw_data.owner == '' or flaw_data.owner is None:
            flaw_data.owner = owner
            try:
                OSIDB_SESSION.flaws.update(flaw_data.uuid, form_data=flaw_data.to_dict())
                owner_updated = True
                print(f"[+] {cve_id}: Owner updated to '{owner}'")
            except requests.exceptions.HTTPError as e:
                print(f"[!] {cve_id}: Failed to update owner: {e}")
                sys.exit(1)
        else:
            print(f"[i] {cve_id}: Owner already assigned ({flaw_data.owner})")
        
        # Print success summary
        if component_updated or owner_updated:
            print(f"[✓] {cve_id}: Successfully updated")
        else:
            print(f"[✓] {cve_id}: No updates needed")
        
        sys.exit(0)
        
    except Exception as e:
        print(f"[!] {cve_id}: Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
PYTHON_EOF

chmod +x "$PYTHON_SCRIPT"

# Process each CVE - continue even if one fails
SUCCESS_COUNT=0
FAILED_COUNT=0

for CVE_ID in "${CVE_ARRAY[@]}"; do
    if [ -z "$CVE_ID" ]; then
        continue
    fi
    
    echo "----------------------------------------"
    echo "[*] Processing: $CVE_ID"
    
    # Run Python script and capture exit code, but don't exit on failure
    if python3 "$PYTHON_SCRIPT" "$COMPONENT" "$OWNER" "$CVE_ID" 2>&1; then
        ((SUCCESS_COUNT++))
    else
        EXIT_CODE=$?
        echo "[!] Failed with exit code: $EXIT_CODE"
        ((FAILED_COUNT++))
    fi
    
    echo ""
done

# Cleanup
rm -f "$PYTHON_SCRIPT"

# Print final summary
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Total CVEs processed: $TOTAL_CVES"
echo "Successfully updated: $SUCCESS_COUNT"
echo "Failed: $FAILED_COUNT"
echo "========================================"

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[✓] Successfully updated $SUCCESS_COUNT CVE flaw(s)!"
fi

if [ $FAILED_COUNT -gt 0 ]; then
    echo "[!] Warning: $FAILED_COUNT CVE(s) failed to update"
fi

exit 0
