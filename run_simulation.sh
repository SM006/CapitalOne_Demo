#!/bin/bash
set -e

LOG_DIR="${LOG_DIR:-/demo/logs}"
mkdir -p "$LOG_DIR"

echo "=========================================================="
echo " Capital One Breach Demo: Zeek SSRF Detection Simulation"
echo "=========================================================="

echo "[1/7] Configuring loopback IP alias 169.254.169.254/32..."
if command -v ip >/dev/null 2>&1; then
    ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
elif command -v ifconfig >/dev/null 2>&1; then
    sudo ifconfig lo0 alias 169.254.169.254 up 2>/dev/null || true
fi

echo "[2/7] Starting toy vulnerable application on 0.0.0.0:8080..."
python3 /demo/vuln_app.py 8080 > /tmp/vuln_app.log 2>&1 &
VULN_PID=$!

echo "[3/7] Starting fake AWS EC2 metadata service on 0.0.0.0:80 (accessible via 169.254.169.254)..."
python3 /demo/fake_metadata.py 0.0.0.0 80 > /tmp/fake_metadata.log 2>&1 &
META_PID=$!

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

# Wait for services to listen
echo "[*] Verifying services readiness..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8080/ >/dev/null && curl -s http://169.254.169.254/ >/dev/null; then
        echo "[+] Both Vulnerable App and Metadata Service are active!"
        break
    fi
    sleep 0.5
done

echo "[4/7] Launching Zeek network monitor on loopback with ssrf_detect.zeek..."
IFACE="lo"
if [[ "$OSTYPE" == "darwin"* ]]; then
    IFACE="lo0"
fi

cd "$LOG_DIR"
rm -f *.log

# -C ignores checksum offloading on loopback interfaces
zeek -C -i "$IFACE" /demo/ssrf_detect.zeek > /tmp/zeek.stdout 2>&1 &
ZEEK_PID=$!
sleep 2
echo "[+] Zeek running (PID: $ZEEK_PID) on interface $IFACE"

echo ""
echo "[5/7] Simulating the SSRF Attack (Capital One Breach Step 1)..."
echo ">> Target: http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
echo ""
EXFIL_CREDS=$(curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production")
echo "$EXFIL_CREDS" | jq . || echo "$EXFIL_CREDS"

echo ""
echo "[6/7] Simulating S3 Exfiltration Access (Capital One Breach Step 2)..."
echo ">> Target: http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
echo ""
S3_RESP=$(curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync")
echo "$S3_RESP" | jq . || echo "$S3_RESP"

echo ""
echo "[*] Waiting for Zeek capture buffer to flush to disk..."
sleep 3

echo "[7/7] Stopping Zeek to finalize log generation..."
kill -INT $ZEEK_PID 2>/dev/null || true
wait $ZEEK_PID 2>/dev/null || true
ZEEK_PID=""

echo ""
echo "=========================================================="
echo " DEMO RESULTS & LOG CORRELATION ARTIFACTS"
echo "=========================================================="

echo ""
echo "=========================================================="
echo " 1. HTTP Log (http.log) - Full Visibility into HTTP Requests"
echo "=========================================================="
if [ -f http.log ]; then
    echo "Columns: ts | uid | id.orig_h | id.resp_h | id.resp_p | method | host | uri | status_code"
    echo "------------------------------------------------------------------------------------------------"
    zeek-cut ts uid id.orig_h id.resp_h id.resp_p method host uri status_code < http.log
else
    echo "http.log not generated"
fi

echo ""
echo "=========================================================="
echo " 2. Connection Log (conn.log) - Transport Layer Records"
echo "=========================================================="
if [ -f conn.log ]; then
    echo "Columns: uid | id.orig_h | id.resp_h | id.resp_p | proto | orig_bytes | resp_bytes"
    echo "----------------------------------------------------------------------------------"
    zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log
else
    echo "conn.log not generated"
fi

echo ""
echo "=========================================================="
echo " 3. Notice Log (notice.log) - Automated Real-Time Alert!"
echo "=========================================================="
if [ -f notice.log ]; then
    echo "Columns: ts | note | msg | id.orig_h | id.resp_h"
    echo "----------------------------------------------------------------------------------"
    zeek-cut ts note msg id.orig_h id.resp_h < notice.log
else
    echo "notice.log not generated"
fi

echo ""
echo "=========================================================="
echo " 4. Cross-Log Correlation by UID (Analyst Investigation)"
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
        echo ""
    done
fi

echo "=========================================================="
echo " Simulation Complete! All logs saved in: $LOG_DIR"
echo "=========================================================="
