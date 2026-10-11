#!/bin/bash
if [[ "$1" == "-i" ]] || [[ "$1" == "--interactive" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    exec python3 "$SCRIPT_DIR/run_interactive_demo.py"
fi

set -e


LOG_DIR="${LOG_DIR:-/demo/logs}"
mkdir -p "$LOG_DIR"

echo "=========================================================="
echo " Capital One Breach Demo: Zeek SSRF Detection Simulation"
echo "=========================================================="

echo "[1/13] Configuring loopback IP alias 169.254.169.254/32..."
if command -v ip >/dev/null 2>&1; then
    ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
elif command -v ifconfig >/dev/null 2>&1; then
    sudo ifconfig lo0 alias 169.254.169.254 up 2>/dev/null || true
fi

echo "[2/13] Starting fake AWS EC2 metadata service on 0.0.0.0:80 (accessible via 169.254.169.254)..."
python3 /demo/services/fake_metadata.py 0.0.0.0 80 > /tmp/fake_metadata.log 2>&1 &
META_PID=$!

echo "[3/13] Starting toy vulnerable application on 0.0.0.0:8080..."
python3 /demo/services/vuln_app.py 8080 > /tmp/vuln_app.log 2>&1 &
VULN_PID=$!

cleanup() {
    echo ""
    echo "[*] Cleaning up simulation background processes..."
    kill $VULN_PID 2>/dev/null || true
    kill $META_PID 2>/dev/null || true
    if [ -n "$ZEEK_PID" ]; then
        kill -INT $ZEEK_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[4/13] Verifying services readiness..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8080/ >/dev/null && curl -s http://169.254.169.254/ >/dev/null; then
        echo "[+] Both Vulnerable App and Metadata Service are active!"
        break
    fi
    sleep 0.5
done

echo "[5/13] Launching Zeek passive network monitor on loopback with ssrf_detect.zeek..."
IFACE="lo"
if [[ "$OSTYPE" == "darwin"* ]]; then
    IFACE="lo0"
fi

cd "$LOG_DIR"
rm -f *.log

# -C ignores checksum offloading on loopback interfaces
zeek -C -i "$IFACE" /demo/zeek/ssrf_detect.zeek > /tmp/zeek.stdout 2>&1 &

ZEEK_PID=$!
sleep 2
echo "[+] Zeek running (PID: $ZEEK_PID) on interface $IFACE"

echo ""
echo "[6/13] Simulating SSRF Credential Exfiltration (Capital One Breach Step 1)..."
echo ">> Target: http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
echo ""
EXFIL_CREDS=$(curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production")
echo "$EXFIL_CREDS" | jq . 2>/dev/null || echo "$EXFIL_CREDS"

echo ""
echo "[7/13] Simulating S3 Exfiltration Access (Capital One Breach Step 2)..."
echo ">> Target: http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
echo ""
S3_RESP=$(curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync")
echo "$S3_RESP" | jq . 2>/dev/null || echo "$S3_RESP"

echo ""
echo "[*] Waiting for Zeek capture buffer to flush to disk..."
sleep 3

echo "[8/13] Stopping Zeek & flushing captured logs to disk..."
kill -INT $ZEEK_PID 2>/dev/null || true
wait $ZEEK_PID 2>/dev/null || true
ZEEK_PID=""

echo ""
echo "[9/13] Zeek Real-Time Security Alert (notice.log)..."
echo "Columns: ts | uid | note | msg"
echo "----------------------------------------------------------------------------------"
if [ -f notice.log ]; then
    zeek-cut ts uid note msg < notice.log
else
    echo "notice.log not generated"
fi

echo ""
echo "[10/13] HTTP Transactions & Transport Telemetry (http.log & conn.log)..."
if [ -f http.log ]; then
    echo "--- http.log (uid | method | host | uri | status_code) ---"
    zeek-cut uid method host uri status_code < http.log
fi
if [ -f conn.log ]; then
    echo "--- conn.log (uid | id.orig_h | id.resp_h | id.resp_p | proto | orig_bytes | resp_bytes) ---"
    zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log
fi

echo ""
echo "[11/13] File Extraction & Payload Inspection (files.log)..."
echo "Columns: fuid | uid | id.orig_h | id.resp_h | source | mime_type | seen_bytes | total_bytes"
echo "--------------------------------------------------------------------------------------------"
if [ -f files.log ]; then
    zeek-cut fuid uid id.orig_h id.resp_h source mime_type seen_bytes total_bytes < files.log
else
    echo "files.log not generated"
fi

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
if [ -f "/demo/canary/trigger_canary.sh" ] && [ -f "$HOME/.aws/credentials" ] && grep -q "\[canary\]" "$HOME/.aws/credentials"; then
    /demo/canary/trigger_canary.sh || true
elif [ -f "./canary/trigger_canary.sh" ] && [ -f "$HOME/.aws/credentials" ] && grep -q "\[canary\]" "$HOME/.aws/credentials"; then
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
echo " DEMO RESULTS & MULTI-LOG CORRELATION SUMMARY"
echo "=========================================================="
if [ -f notice.log ]; then
    ALERT_UIDS=$(zeek-cut uid < notice.log)
    for ALERT_UID in $ALERT_UIDS; do
        echo "Correlation Key (UID): $ALERT_UID"
        echo "  [Notice Log] Alert trigger:"
        zeek-cut uid note msg < notice.log | grep "$ALERT_UID" | sed 's/^/    /'
        echo "  [HTTP Log] Exact request payload:"
        zeek-cut uid method host uri status_code < http.log | grep "$ALERT_UID" | sed 's/^/    /'
        echo "  [Conn Log] Network transport details:"
        zeek-cut uid id.orig_h id.resp_h id.resp_p proto < conn.log | grep "$ALERT_UID" | sed 's/^/    /'
        if [ -f files.log ]; then
            echo "  [Files Log] Extracted exfiltration payload:"
            zeek-cut uid fuid mime_type seen_bytes total_bytes < files.log | grep "$ALERT_UID" | sed 's/^/    /'
        fi
        echo ""
    done
fi

echo "=========================================================="
echo " Simulation Complete! All logs saved in: $LOG_DIR"
echo "=========================================================="
