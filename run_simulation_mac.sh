#!/bin/bash
# Native macOS Execution Script (Requires 'brew install zeek')
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

echo "[1/7] Configuring macOS loopback IP alias 169.254.169.254 on lo0..."
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

echo "[2/7] Starting toy vulnerable application on 0.0.0.0:8080..."
python3 vuln_app.py 8080 > /tmp/vuln_app.log 2>&1 &
VULN_PID=$!

echo "[3/7] Starting fake AWS EC2 metadata service on 0.0.0.0:80..."
python3 fake_metadata.py 0.0.0.0 80 > /tmp/fake_metadata.log 2>&1 &
META_PID=$!

echo "[*] Verifying services readiness..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8080/ >/dev/null && curl -s http://169.254.169.254/ >/dev/null; then
        echo "[+] Services active!"
        break
    fi
    sleep 0.5
done

echo "[4/7] Launching Zeek network monitor on lo0 with ssrf_detect.zeek..."
cd "$LOG_DIR"
rm -f *.log

sudo zeek -C -i lo0 "$(pwd)/../ssrf_detect.zeek" > /tmp/zeek.stdout 2>&1 &
ZEEK_PID=$!
sleep 2

echo "[5/7] Simulating SSRF Attack..."
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
echo ""

echo "[6/7] Simulating S3 Sync..."
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
echo ""

sleep 3
echo "[7/7] Stopping Zeek..."
sudo kill -INT $ZEEK_PID 2>/dev/null || true
wait $ZEEK_PID 2>/dev/null || true
ZEEK_PID=""

echo ""
echo "=========================================================="
echo " Results captured in $LOG_DIR:"
echo "=========================================================="
zeek-cut ts uid id.orig_h id.resp_h uri < http.log || true
zeek-cut ts note msg < notice.log || true
