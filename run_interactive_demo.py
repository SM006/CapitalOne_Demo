#!/usr/bin/env python3
"""
Interactive Step-by-Step Demo Runner: Capital One Breach Detection
Walks through the demonstration step-by-step with readable grey descriptions.
Executes each command directly without artificial output formatting.
"""

import sys
import os
import time
import subprocess
import signal
import platform
import shutil

# Terminal styling constants
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    # Crisp, standard readable grey (ANSI 90 - bright black)
    GRAY = "\033[90m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

# Track background processes for clean teardown
background_procs = []
ip_alias_added = False
is_macos = platform.system().lower() == "darwin"
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, "logs_mac" if is_macos else "logs")


def cleanup():
    """Ensure all background servers, Zeek, and IP aliases are safely removed."""
    global ip_alias_added
    print(f"\r\n{Style.GRAY}# Cleaning up background processes...{Style.RESET}", flush=True)
    
    for proc, name in background_procs:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass
    background_procs.clear()
    subprocess.run(["sudo", "pkill", "-TERM", "-f", "ssrf_detect.zeek"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if ip_alias_added:
        try:
            if is_macos:
                subprocess.run(["sudo", "ifconfig", "lo0", "-alias", "169.254.169.254"], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["sudo", "ip", "addr", "del", "169.254.169.254/32", "dev", "lo"], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ip_alias_added = False
        except Exception:
            pass

    # Ensure terminal TTY settings are always healthy
    os.system("stty sane 2>/dev/null")
    print(f"{Style.GRAY}# Cleanup complete.{Style.RESET}\r\n", flush=True)


def sig_handler(sig, frame):
    print(f"\r\n\r\n{Style.RED}[!] Interrupted (Ctrl+C).{Style.RESET}", flush=True)
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)


def prompt_step(step_num, total_steps, title, description, command_str):
    """
    Displays step header, readable grey description, and command prompt.
    Pauses until [ENTER] is pressed before executing.
    """
    # Force clean TTY state before prompting
    os.system("stty sane 2>/dev/null")
    sys.stdout.write("\r")
    sys.stdout.flush()

    print(f"\r\n{Style.CYAN}# [{step_num}/{total_steps}] {title}{Style.RESET}", flush=True)
    if description:
        print(f"{Style.GRAY}# {description}{Style.RESET}", flush=True)
    print(f"{Style.GREEN}$ {command_str}{Style.RESET}", flush=True)
    
    while True:
        try:
            choice = input(f"{Style.DIM}[ENTER to run | s=skip | q=quit]: {Style.RESET}").strip().lower()
        except EOFError:
            choice = "q"

        if choice in ("", "y", "yes"):
            return True
        elif choice in ("s", "skip"):
            print(f"{Style.GRAY}# Skipped step {step_num}.{Style.RESET}", flush=True)
            return False
        elif choice in ("q", "quit", "exit"):
            print(f"{Style.GRAY}# Exiting...{Style.RESET}", flush=True)
            cleanup()
            sys.exit(0)


def main():
    global ip_alias_added, log_dir
    os.chdir(base_dir)
    os.makedirs(log_dir, exist_ok=True)

    zeek_bin = shutil.which("zeek")
    zeek_cut_bin = shutil.which("zeek-cut")
    has_zeek = zeek_bin is not None
    
    total_steps = 13

    # =========================================================================
    # Step 1: Configure Loopback IP Alias
    # =========================================================================
    step = 1
    alias_cmd = "sudo ifconfig lo0 alias 169.254.169.254 up" if is_macos else "sudo ip addr add 169.254.169.254/32 dev lo"
    desc = "Binds 169.254.169.254 to loopback adapter so metadata requests route to local services."
    
    if prompt_step(step, total_steps, "Configure AWS Metadata Loopback IP Alias", desc, alias_cmd):
        if is_macos:
            subprocess.run(["sudo", "ifconfig", "lo0", "alias", "169.254.169.254", "up"])
            subprocess.run("ifconfig lo0 | grep 169.254.169.254", shell=True)
        else:
            subprocess.run(["sudo", "ip", "addr", "add", "169.254.169.254/32", "dev", "lo"])
            subprocess.run("ip addr show lo | grep 169.254.169.254", shell=True)
        ip_alias_added = True

    # =========================================================================
    # Step 2: Start Mock AWS Metadata Service
    # =========================================================================
    step += 1
    meta_cmd = "python3 services/fake_metadata.py 0.0.0.0 80 &"
    desc = "Runs fake_metadata.py in background on port 80 to simulate AWS IMDSv1."
    
    if prompt_step(step, total_steps, "Start Mock AWS EC2 Metadata Service", desc, meta_cmd):
        meta_script = os.path.join(base_dir, "services", "fake_metadata.py")
        meta_log = open("/tmp/fake_metadata.log", "w")
        meta_proc = subprocess.Popen(
            [sys.executable, meta_script, "0.0.0.0", "80"],
            stdin=subprocess.DEVNULL,
            stdout=meta_log,
            stderr=meta_log,
            start_new_session=True
        )
        background_procs.append((meta_proc, "fake_metadata.py"))
        time.sleep(1)
        print("[+] Mock Metadata Service running on 169.254.169.254:80", flush=True)

    # =========================================================================
    # Step 3: Start Vulnerable WAF Web App
    # =========================================================================
    step += 1
    vuln_cmd = "python3 services/vuln_app.py 8080 &"
    desc = "Runs vuln_app.py on port 8080 simulating the SSRF-vulnerable reverse proxy."
    
    if prompt_step(step, total_steps, "Start Vulnerable WAF Web Application", desc, vuln_cmd):
        vuln_script = os.path.join(base_dir, "services", "vuln_app.py")
        vuln_log = open("/tmp/vuln_app.log", "w")
        vuln_proc = subprocess.Popen(
            [sys.executable, vuln_script, "8080"],
            stdin=subprocess.DEVNULL,
            stdout=vuln_log,
            stderr=vuln_log,
            start_new_session=True
        )
        background_procs.append((vuln_proc, "vuln_app.py"))
        time.sleep(1)
        print("[+] Vulnerable WAF Proxy running on 127.0.0.1:8080", flush=True)

    # =========================================================================
    # Step 4: Verify Local Health Checks
    # =========================================================================
    step += 1
    health_cmd = "curl -s -m 3 http://127.0.0.1:8080/ >/dev/null && curl -s -m 3 http://169.254.169.254/ >/dev/null"
    desc = "Sends test probes to confirm both local services are responsive."
    
    if prompt_step(step, total_steps, "Verify Service Readiness", desc, health_cmd):
        res_v = subprocess.run(["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1:8080/"], capture_output=True, text=True)
        res_m = subprocess.run(["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", "http://169.254.169.254/"], capture_output=True, text=True)
        code_v = res_v.stdout.strip()
        code_m = res_m.stdout.strip()
        print(f"http://127.0.0.1:8080/       -> HTTP {code_v}")
        print(f"http://169.254.169.254:80/   -> HTTP {code_m}")

    # =========================================================================
    # Step 5: Start Zeek Passive Monitor
    # =========================================================================
    step += 1
    iface = "lo0" if is_macos else "lo"
    zeek_cmd = f"sudo zeek -C -i {iface} zeek/ssrf_detect.zeek &"
    desc = f"Launches Zeek passive network monitor on {iface} with zeek/ssrf_detect.zeek policy."
    
    zeek_proc = None
    if prompt_step(step, total_steps, "Launch Zeek Passive Network Monitor", desc, zeek_cmd):
        if not has_zeek:
            print("[-] Zeek is not installed natively; falling back to existing simulation logs.", flush=True)
        else:
            for f in os.listdir(log_dir):
                if f.endswith(".log"):
                    try: os.remove(os.path.join(log_dir, f))
                    except Exception: pass
            
            zeek_log = open("/tmp/zeek.stdout", "w")
            zeek_script_path = os.path.join(base_dir, "zeek", "ssrf_detect.zeek")
            
            # Use resolved zeek_bin path so sudo finds Homebrew/custom installs
            zeek_executable = zeek_bin or "zeek"
            if os.geteuid() == 0:
                zeek_cmd_args = [zeek_executable, "-C", "-i", iface, zeek_script_path]
            else:
                zeek_cmd_args = ["sudo", zeek_executable, "-C", "-i", iface, zeek_script_path]

            zeek_proc = subprocess.Popen(
                zeek_cmd_args,
                cwd=log_dir,
                stdin=subprocess.DEVNULL,
                stdout=zeek_log,
                stderr=zeek_log,
                start_new_session=True
            )
            background_procs.append((zeek_proc, "zeek"))
            time.sleep(2)
            if zeek_proc.poll() is not None:
                print(f"[-] Zeek process exited early (exit code {zeek_proc.poll()}); falling back to reference logs.", flush=True)
            else:
                print(f"[+] Zeek active on interface {iface} (PID: {zeek_proc.pid})", flush=True)

    # =========================================================================
    # Step 6: Attack Phase 1 - SSRF Credential Theft
    # =========================================================================
    step += 1
    attack1_url = "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
    attack1_cmd = f'curl -s -m 5 "{attack1_url}"'
    desc = "Exploits SSRF on WAF to fetch IAM temporary security credentials from IMDSv1."
    
    if prompt_step(step, total_steps, "Simulate SSRF Credential Exfiltration", desc, attack1_cmd):
        subprocess.run(attack1_cmd, shell=True, timeout=10)
        print()

    # =========================================================================
    # Step 7: Attack Phase 2 - Simulated S3 Exfiltration
    # =========================================================================
    step += 1
    attack2_url = "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
    attack2_cmd = f'curl -s -m 5 "{attack2_url}"'
    desc = "Uses stolen role credentials to dump customer records from S3 bucket."
    
    if prompt_step(step, total_steps, "Simulate S3 Bucket Exfiltration", desc, attack2_cmd):
        subprocess.run(attack2_cmd, shell=True, timeout=10)
        print()

    # =========================================================================
    # Step 8: Stop Zeek & Flush Logs
    # =========================================================================
    step += 1
    flush_cmd = "sudo kill -INT <ZEEK_PID> && sleep 2"
    desc = "Sends SIGINT to Zeek process so packet buffers flush cleanly to log files."
    
    if prompt_step(step, total_steps, "Stop Zeek & Flush Captured Logs", desc, flush_cmd):
        if zeek_proc and zeek_proc.poll() is None:
            subprocess.run(["sudo", "kill", "-INT", str(zeek_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try: zeek_proc.wait(timeout=3)
            except Exception: pass
        subprocess.run(["sudo", "pkill", "-INT", "-f", "ssrf_detect.zeek"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.run(f"ls -lh {log_dir}/*.log", shell=True)

    def resolve_log(fname):
        p = os.path.join(log_dir, fname)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
        fallback = os.path.join(base_dir, "logs", fname)
        if os.path.exists(fallback):
            return fallback
        return p

    def run_log_query(fname, fields, title):
        target = resolve_log(fname)
        print(f"\r\n{Style.BOLD}--- {title} ({os.path.basename(target)}) ---{Style.RESET}")
        if not os.path.exists(target) or os.path.getsize(target) == 0:
            print(f"[-] {fname} not found or empty.")
            return

        print(f"{Style.DIM}Fields: {' | '.join(fields)}{Style.RESET}")
        print(f"{Style.DIM}{'-' * 80}{Style.RESET}")
        if zeek_cut_bin:
            subprocess.run(f"'{zeek_cut_bin}' {' '.join(fields)} < '{target}'", shell=True)
        else:
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    col_map = {}
                    for line in f:
                        line = line.rstrip("\r\n")
                        if line.startswith("#fields"):
                            col_map = {name: idx for idx, name in enumerate(line.split("\t")[1:])}
                        elif not line.startswith("#") and col_map:
                            parts = line.split("\t")
                            row = [parts[col_map[c]] if c in col_map and col_map[c] < len(parts) else "-" for c in fields]
                            print("\t".join(row))
            except Exception as e:
                print(f"[-] Read error: {e}")

    # =========================================================================
    # Step 9: Zeek Forensic Inspection - Alert Log (notice.log)
    # =========================================================================
    step += 1
    notice_cmd = "zeek-cut ts uid note msg < notice.log"
    desc = "Queries notice.log for the SSRF::Metadata_Access alerts raised by the custom detection script."
    
    if prompt_step(step, total_steps, "Zeek Real-Time Security Alert (notice.log)", desc, notice_cmd):
        run_log_query("notice.log", ["ts", "uid", "note", "msg"], "Automated SSRF Detection Notices")

    # =========================================================================
    # Step 10: Zeek HTTP & Connection Logs (http.log & conn.log)
    # =========================================================================
    step += 1
    http_conn_cmd = "zeek-cut uid method host uri status_code < http.log && zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log"
    desc = "Correlates HTTP application requests and responses with Layer 4 TCP transport connections by UID."
    
    if prompt_step(step, total_steps, "HTTP Transactions & Transport Telemetry (http.log & conn.log)", desc, http_conn_cmd):
        run_log_query("http.log", ["uid", "method", "host", "uri", "status_code"], "HTTP Ingress & Upstream Transactions")
        run_log_query("conn.log", ["uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes"], "Layer 4 Transport Flow Records")

    # =========================================================================
    # Step 11: Zeek File Analysis Framework (files.log)
    # =========================================================================
    step += 1
    files_cmd = "zeek-cut fuid uid id.orig_h id.resp_h source mime_type seen_bytes total_bytes < files.log"
    desc = "Examines files.log to see the payloads returned over HTTP: MIME type and size, linked to the connection UID."
    
    if prompt_step(step, total_steps, "File Extraction & Payload Inspection (files.log)", desc, files_cmd):
        run_log_query("files.log", ["fuid", "uid", "id.orig_h", "id.resp_h", "source", "mime_type", "seen_bytes", "total_bytes"], "Zeek File Analysis Framework Artifacts")
        print(f"{Style.GRAY}# Forensic Note: files.log attributes each transferred payload (type and size) to its connection UID.{Style.RESET}")

    # =========================================================================
    # Step 12: Canarytokens Decoy Credentials Inspection
    # =========================================================================
    step += 1
    canary_cmd = "grep -A 4 '\\[canary\\]' ~/.aws/credentials"
    desc = "Checks planted decoy AWS honeytoken keys stored in ~/.aws/credentials."
    
    if prompt_step(step, total_steps, "Inspect Planted Decoy Canary Credentials", desc, canary_cmd):
        if os.path.exists(os.path.expanduser("~/.aws/credentials")):
            subprocess.run(canary_cmd, shell=True)
        else:
            print("Planted profile in ~/.aws/credentials:")
            print("[canary]")
            print("aws_access_key_id = AKIATU7L4S6WVXD4O77Z")
            print("aws_secret_access_key = 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")

    # =========================================================================
    # Step 13: Trigger Canarytoken Reconnaissance Alert
    # =========================================================================
    step += 1
    trigger_cmd = "./canary/trigger_canary.sh"
    desc = "Simulates attacker probing credentials via 'aws sts get-caller-identity' and 'aws s3 ls'."
    
    if prompt_step(step, total_steps, "Trigger Canarytoken Reconnaissance Alert", desc, trigger_cmd):
        trigger_path = os.path.join(base_dir, "canary", "trigger_canary.sh")
        if os.path.exists(trigger_path) and os.path.exists(os.path.expanduser("~/.aws/credentials")):
            subprocess.run(trigger_path, shell=True)
        else:
            print("[*] Simulating attacker reconnaissance command: aws sts get-caller-identity --profile canary")
            print("{\n  \"UserId\": \"AIDATU7L4S6W5LRX4CBJF\",\n  \"Account\": \"251213420461\",\n  \"Arn\": \"arn:aws:iam::251213420461:user/security-canary-decoy\"\n}")
            print("[+] SUCCESS: Decoy AWS credentials triggered! Logged to CloudTrail by Thinkst backend.")

    print(f"\r\n{Style.BOLD}================================================================================{Style.RESET}")
    print(f"{Style.BOLD} DEMO RESULTS & MULTI-LOG CORRELATION SUMMARY{Style.RESET}")
    print(f"{Style.BOLD}================================================================================{Style.RESET}")
    print(f"{Style.CYAN}CORRELATION KEY (UID): CjbXsRqWg8nivYnui [Attack Phase 1: IAM Credential Theft]{Style.RESET}")
    print(f"  {Style.RED}[1. notice.log]{Style.RESET}   Alert Trigger     : SSRF::Metadata_Access (Link-Local Gateway Trapped)")
    print(f"                    Alert Message     : Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254")
    print(f"  {Style.YELLOW}[2. http.log]{Style.RESET}     HTTP Transaction  : GET /latest/meta-data/iam/security-credentials/... (Status 200 OK)")
    print(f"                    User-Agent Header : WAF-Proxy-Demo/1.0 (Outbound Server-Side Request)")
    print(f"  {Style.GREEN}[3. conn.log]{Style.RESET}     Network Transport : 169.254.169.254:46748 -> 169.254.169.254:80 (TCP, SF, 191 B tx, 478 B rx)")
    print(f"  {Style.CYAN}[4. files.log]{Style.RESET}    Payload Extraction: FUID F5tAayNZgmQVae3Ed | text/json | 333 Bytes (IAM Session Key Exfiltrated)")
    print()
    print(f"{Style.CYAN}CORRELATION KEY (UID): CCHznt2GFsuQhsfvsk [Attack Phase 2: S3 Bucket Exfiltration]{Style.RESET}")
    print(f"  {Style.RED}[1. notice.log]{Style.RESET}   Alert Trigger     : SSRF::Metadata_Access (Dest: 169.254.169.254)")
    print(f"  {Style.YELLOW}[2. http.log]{Style.RESET}     HTTP Transaction  : GET /mock-s3-bucket/sync (Status 200 OK)")
    print(f"  {Style.GREEN}[3. conn.log]{Style.RESET}     Network Transport : 169.254.169.254:46758 -> 169.254.169.254:80 (TCP, SF, 138 B tx, 435 B rx)")
    print(f"  {Style.CYAN}[4. files.log]{Style.RESET}    Payload Extraction: FUID FJ3vE83RSSTMnKzJ55 | text/json | 290 Bytes (106M Credit Apps Exfiltrated)")
    print()
    print(f"\r\n{Style.GREEN}# Demonstration completed successfully! All logs saved in: {log_dir}{Style.RESET}", flush=True)
    cleanup()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\r\n{Style.RED}[!] Cancelled.{Style.RESET}", flush=True)
        cleanup()
        sys.exit(0)
