#!/bin/bash
# Canarytoken Planter Script
# Simulates planting decoy AWS credentials on an endpoint / server.

set -e

echo "=========================================================="
echo " Capital One Breach Demo: Canarytoken Credential Planter"
echo "=========================================================="
echo ""
echo "1. Go to https://canarytokens.org"
echo "2. Select 'AWS Keys' token type"
echo "3. Enter your email/webhook to receive alerts"
echo "4. Copy the generated Access Key ID and Secret Access Key"
echo ""

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./plant_canary.sh <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS_KEY>"
    echo ""
    read -p "Enter Canary AWS Access Key ID: " CANARY_KEY
    read -p "Enter Canary AWS Secret Access Key: " CANARY_SECRET
else
    CANARY_KEY="$1"
    CANARY_SECRET="$2"
fi

if [ -z "$CANARY_KEY" ] || [ -z "$CANARY_SECRET" ]; then
    echo "Error: Key and Secret must not be empty."
    exit 1
fi

python3 -c "
import os, sys

path = os.path.expanduser('~/.aws/credentials')
os.makedirs(os.path.dirname(path), exist_ok=True)

lines = []
if os.path.exists(path):
    with open(path, 'r') as f:
        in_canary = False
        for line in f:
            if line.strip() == '[canary]':
                in_canary = True
                continue
            elif in_canary and line.startswith('['):
                in_canary = False
            if not in_canary:
                lines.append(line)

canary_block = f'''
[canary]
aws_access_key_id = {sys.argv[1]}
aws_secret_access_key = {sys.argv[2]}
'''

with open(path, 'w') as f:
    f.writelines(lines)
    f.write(canary_block.strip() + '\n')
" "$CANARY_KEY" "$CANARY_SECRET"


echo ""
echo "[+] Decoy AWS credentials planted successfully in ~/.aws/credentials:"
echo "----------------------------------------------------------"
grep -A 2 "\[canary\]" "$HOME/.aws/credentials"
echo "----------------------------------------------------------"
echo ""
echo "Next step: Run ./trigger_canary.sh to simulate the attacker using these credentials."
