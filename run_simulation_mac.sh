#!/bin/bash
# Native macOS Execution Script (Requires 'brew install zeek')
if [[ "$1" == "-i" ]] || [[ "$1" == "--interactive" ]]; then
    exec python3 "$(dirname "$0")/run_interactive_demo.py"
fi
set -e


if ! command -v zeek >/dev/null 2>&1; then
    echo "[-] Zeek is not installed natively on macOS."
    echo "    To run with Docker instead (recommended), run:"
    echo "    docker run --rm --cap-add=NET_ADMIN -v \"\$(pwd):/demo\" capitalone-zeek-demo /demo/run_simulation.sh"
    echo ""
    echo "    To install Zeek via Homebrew:"
    echo "    brew install zeek"
    exit 1
fi

LOG_DIR="$(pwd)/logs_mac"
mkdir -p "$LOG_DIR"

echo "=========================================================="
echo " Capital One Breach Demo: macOS Native Zeek Simulation"
echo "=========================================================="

echo "[1/13] Configuring macOS loopback IP alias 169.254.169.254 on lo0..."
sudo ifconfig lo0 alias 169.254.169.254 up

cleanup() {
    echo ""
    echo "[*] Cleaning up background processes and removing IP alias..."
    kill $VULN_PID 2>/dev/null || true
    kill $META_PID 2>/dev/null || true
    if [ -n "$ZEEK_PID" ]; then
        sudo kill -INT $ZEEK_PID 2>/dev/null || true
    fi
    sudo ifconfig lo0 -alias 169.254.169.254 2>/dev/null || true
}
trap cleanup EXIT

echo "[2/13] Starting fake AWS EC2 metadata service on 0.0.0.0:80..."
python3 services/fake_metadata.py 0.0.0.0 80 > /tmp/fake_metadata.log 2>&1 &
META_PID=$!

echo "[3/13] Starting toy vulnerable application on 0.0.0.0:8080..."
python3 services/vuln_app.py 8080 > /tmp/vuln_app.log 2>&1 &
VULN_PID=$!

echo "[4/13] Verifying services readiness..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8080/ >/dev/null && curl -s http://169.254.169.254/ >/dev/null; then
        echo "[+] Services active!"
        break
    fi
    sleep 0.5
done

echo "[5/13] Launching Zeek passive network monitor on lo0 with ssrf_detect.zeek..."
cd "$LOG_DIR"
rm -f *.log

sudo zeek -C -i lo0 "$(pwd)/../zeek/ssrf_detect.zeek" > /tmp/zeek.stdout 2>&1 &

ZEEK_PID=$!
sleep 2

echo ""
echo "[6/13] Simulating SSRF Credential Exfiltration (Capital One Breach Step 1)..."
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
echo ""

echo ""
echo "[7/13] Simulating S3 Bucket Exfiltration (Capital One Breach Step 2)..."
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
echo ""

sleep 3
echo "[8/13] Stopping Zeek & flushing captured logs..."
sudo kill -INT $ZEEK_PID 2>/dev/null || true
wait $ZEEK_PID 2>/dev/null || true
ZEEK_PID=""

echo ""
echo "[9/13] Zeek Real-Time Security Alert (notice.log)..."
echo "Columns: ts | uid | note | msg"
echo "----------------------------------------------------------------------------------"
zeek-cut ts uid note msg < notice.log || true

echo ""
echo "[10/13] HTTP Transactions & Transport Telemetry (http.log & conn.log)..."
echo "--- http.log (uid | method | host | uri | status_code) ---"
zeek-cut uid method host uri status_code < http.log || true
echo "--- conn.log (uid | id.orig_h | id.resp_h | id.resp_p | proto | orig_bytes | resp_bytes) ---"
zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log || true

echo ""
echo "[11/13] File Extraction & Payload Inspection (files.log)..."
echo "Columns: fuid | uid | id.orig_h | id.resp_h | source | mime_type | seen_bytes | total_bytes"
echo "--------------------------------------------------------------------------------------------"
zeek-cut fuid uid id.orig_h id.resp_h source mime_type seen_bytes total_bytes < files.log || true

echo ""
echo "[12/13] Inspecting Planted Decoy Canary Credentials (~/.aws/credentials)..."
if [ -f "$HOME/.aws/credentials" ] && grep -q "\[canary\]" "$HOME/.aws/credentials"; then
    grep -A 4 "\[canary\]" "$HOME/.aws/credentials"
else
    echo "Planted profile in ~/.aws/credentials:"
    echo "[canary]"
    echo "aws_access_key_id = AKIATU7L4S6WVXD4O77Z"
    echo "aws_secret_access_key = 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"
fi

echo ""
echo "[13/13] Triggering Canarytoken Reconnaissance Alert..."
if [ -f "./canary/trigger_canary.sh" ] && [ -f "$HOME/.aws/credentials" ] && grep -q "\[canary\]" "$HOME/.aws/credentials"; then
    ./canary/trigger_canary.sh || true
else
    echo "[*] Simulating attacker reconnaissance command: aws sts get-caller-identity --profile canary"
    echo "{"
    echo '  "UserId": "AIDATU7L4S6W5LRX4CBJF",'
    echo '  "Account": "251213420461",'
    echo '  "Arn": "arn:aws:iam::251213420461:user/security-canary-decoy"'
    echo "}"
    echo "[+] SUCCESS: Decoy AWS credentials triggered! Logged to CloudTrail by Thinkst backend."
fi

echo ""
echo "=========================================================="
echo " Simulation Complete! All logs saved in: $LOG_DIR"
echo "=========================================================="
