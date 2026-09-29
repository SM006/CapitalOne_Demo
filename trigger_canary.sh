#!/bin/bash
# Canarytoken Trigger Script
# Simulates the attacker using the stolen/planted canary credentials.

set -e

echo "=========================================================="
echo " Capital One Breach Demo: Canarytoken Trigger Execution"
echo "=========================================================="
echo ""

AWS_CRED_FILE="$HOME/.aws/credentials"

if [ ! -f "$AWS_CRED_FILE" ] || ! grep -q "\[canary\]" "$AWS_CRED_FILE"; then
    echo "[-] Error: Canary credentials profile not found in $AWS_CRED_FILE."
    echo "    Please run ./plant_canary.sh first with your Canarytokens.org keys."
    exit 1
fi

echo "[*] Found [canary] profile in $AWS_CRED_FILE:"
grep -A 2 "\[canary\]" "$AWS_CRED_FILE"
echo ""

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] Trigger Timestamp (UTC): $TIMESTAMP"
echo "[*] Simulating attacker reconnaissance command:"
echo "    $ aws sts get-caller-identity --profile canary --region us-east-1"
echo ""

# Execute AWS STS command
set +e
OUTPUT=$(aws sts get-caller-identity --profile canary --region us-east-1 2>&1)
EXIT_CODE=$?
set -e

echo "------------------- AWS CLI Output -----------------------"
echo "$OUTPUT"
echo "----------------------------------------------------------"
echo ""
echo "[+] SUCCESS: The Canarytoken has been pinged at $TIMESTAMP!"
echo "    The STS request was received by Thinkst's Canary honeypot backend."
echo ""
echo "    Check your registered Canarytoken email or webhook now!"
echo "    You will see an alert containing:"
echo "    - Token Memo: Your token description"
echo "    - Attacker Public IP: Source IP of this machine"
echo "    - Trigger Timestamp: $TIMESTAMP"
echo "    - User-Agent: aws-cli"
echo "    - API Action: sts:GetCallerIdentity"
