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

CANARY_REGION=$(aws configure get region --profile canary 2>/dev/null || echo "us-east-2")
[ -z "$CANARY_REGION" ] && CANARY_REGION="us-east-2"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] Trigger Timestamp (UTC): $TIMESTAMP"
echo "[*] Target Region: $CANARY_REGION"
echo "[*] Simulating attacker reconnaissance commands:"
echo "    1. $ aws sts get-caller-identity --profile canary --region $CANARY_REGION"
echo "    2. $ aws s3 ls --profile canary --region $CANARY_REGION"
echo ""

# Execute AWS STS and S3 commands
set +e
STS_OUTPUT=$(aws sts get-caller-identity --profile canary --region "$CANARY_REGION" 2>&1)
S3_OUTPUT=$(aws s3 ls --profile canary --region "$CANARY_REGION" 2>&1)
set -e

echo "------------------- AWS STS Output -----------------------"
echo "$STS_OUTPUT"
echo "------------------- AWS S3 Output ------------------------"
echo "$S3_OUTPUT"
echo "(Expected: Decoy canary keys have zero IAM permissions, blocking data exfiltration while logging attacker IP to CloudTrail)"
echo "----------------------------------------------------------"
echo ""
echo "[+] SUCCESS: Decoy AWS credentials triggered at $TIMESTAMP!"
echo "    The requests were logged by AWS CloudTrail to Thinkst's monitoring backend."

