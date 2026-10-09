# Capital One Breach Demo: Live Terminal Walkthrough & Script

A presenter runbook for demonstrating the **Capital One SSRF Breach**, **Zeek Network Detection**, and **Thinkst Canarytoken Deception** directly inside your terminal.

---

## Presentation Overview & Flow

| Stage | Duration | Action | Key Takeaway |
|---|---|---|---|
| **Intro** | 1 min | Explain 2019 Capital One Breach context | SSRF on WAF &rarr; AWS IMDSv1 (`169.254.169.254`) &rarr; 4-month dwell time |
| **Demo 1** | 2 min | Run Zeek automated simulation | Instant detection (&lt; 0.01s) via `ssrf_detect.zeek` |
| **Demo 2** | 2 min | Inspect & correlate logs using `zeek-cut` | Single connection `uid` binds Transport, HTTP payload, and Alert |
| **Demo 3** | 2 min | Plant & trigger Canarytoken | Decoy AWS keys trip CloudTrail alarm during attacker discovery |
| **Wrap-up**| 1 min | Architectural remediation | Enforce IMDSv2 session tokens and hop limit = 1 |

---

## Step 0: Pre-Demo Check (Before You Present)

Open your terminal and ensure you are in the project folder:

```bash
cd /Users/shreya/Desktop/CapitalOne_Demo
```

Verify Docker is running:
```bash
docker ps
```

---

## Step 1: Context & Problem Statement (What to Say)

> **Speaker Script:**  
> *"In March 2019, Capital One suffered one of the largest cloud data breaches in history. An attacker exploited an SSRF flaw on a misconfigured ModSecurity WAF. Because the WAF could make arbitrary outbound requests, the attacker forced it to query the AWS link-local Instance Metadata IP `169.254.169.254`. This leaked temporary IAM credentials that had permission to sync over 700 S3 buckets, exfiltrating 106 million customer credit card records.*  
>  
> *The critical failure was dwell time: the breach ran completely undetected for **108 days** (~4 months) until an external tipster emailed Capital One. Today, I am demonstrating two defense-in-depth controls that reduce that detection time from 4 months to **0 seconds**."*

---

## Step 2: Live Network Detection with Zeek (Demo 1)

### Command to Run:
```bash
docker run --rm --cap-add=NET_ADMIN -v "$(pwd):/demo" capitalone-zeek-demo /demo/run_simulation.sh
```

### What is Happening Live:
1. Aliases the AWS metadata IP `169.254.169.254` on the loopback interface.
2. Boots `services/vuln_app.py` (simulating the vulnerable WAF reverse proxy on port `8080`).
3. Boots `services/fake_metadata.py` (simulating AWS IMDSv1 on port `80`).
4. Launches Zeek passive network monitor with [`zeek/ssrf_detect.zeek`](file:///Users/shreya/Desktop/CapitalOne_Demo/zeek/ssrf_detect.zeek).
5. Fires the simulated attack:

   - Queries `/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production`
   - Queries mock S3 exfiltration endpoint `/mock-s3-bucket/sync`

### Speaker Point:
> *"Notice that as soon as the SSRF payload executes, the credentials and S3 sync responses are returned, but Zeek catches the packet the millisecond it touches the wire."*

---

## Step 3: Zeek Forensic Correlation (Demo 2)

Explain to your audience how Zeek eliminates manual multi-month log correlation.

### Command 1 — View the Security Notice Alert:
```bash
zeek-cut ts uid note msg < logs/notice.log
```

**Expected Terminal Output:**
```text
1790672629.461230  CjbXsRqWg8nivYnui  SSRF::Metadata_Access  Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254 (Requested URI: /latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production)
```

> **Speaker Script:**  
> *"Here is `notice.log`. The policy script immediately raised a high-severity `SSRF::Metadata_Access` notice. Notice the unique Connection UID: `CjbXsRqWg8nivYnui`."*

---

### Command 2 — Correlate with Application HTTP Request:
```bash
zeek-cut uid method host uri status_code < logs/http.log | grep "CjbXsRqWg8nivYnui"
```

**Expected Terminal Output:**
```text
CjbXsRqWg8nivYnui  GET  169.254.169.254  /latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production  200
```

> **Speaker Script:**  
> *"Using that exact same UID, we pivot into `http.log` and see the exact URI, host, and HTTP 200 response."*

---

### Command 3 — Correlate with Transport Connection:
```bash
zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < logs/conn.log | grep "CjbXsRqWg8nivYnui"
```

**Expected Terminal Output:**
```text
CjbXsRqWg8nivYnui  169.254.169.254  169.254.169.254  80  tcp  191  478
```

> **Speaker Script:**  
> *"And in `conn.log`, we have full Layer 4 tracking: source IP, destination IP, port 80, TCP protocol, and exact byte counts. In 2019, Capital One took months to correlate VPC flow logs and application logs manually. Zeek correlates them automatically at capture time."*

---

## Step 4: Canarytokens Decoy Credential Trigger (Demo 3)

Now showcase the second defense layer: active deception.

### 1. Show the Planted Decoy Credentials:
```bash
cat ~/.aws/credentials
```

**Expected Terminal Output:**
```ini
[canary]
aws_access_key_id = AKIATU7L4S6WVXD4O77Z
aws_secret_access_key = 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
```

> **Speaker Script:**  
> *"Even if an adversary bypasses network controls or finds keys on disk, active deception catches them. We have planted monitored decoy credentials under the `[canary]` profile."*

---

### 2. Simulate Attacker Reconnaissance:
```bash
./canary/trigger_canary.sh
```

**Expected Terminal Output:**
```text
[*] Simulating attacker reconnaissance command:
    $ aws sts get-caller-identity --profile canary --region us-east-1

------------------- AWS CLI Output -----------------------
{
    "UserId": "AIDATU7L4S6W5LRX4CBJF",
    "Account": "251213420461",
    "Arn": "arn:aws:iam::251213420461:user/azqjoxxwnbghiqrlgpsilbuqdrvuarunrsbsgtbgvlitxufczq"
}
----------------------------------------------------------
[+] SUCCESS: The Canarytoken has been pinged!
```

> **Speaker Script:**  
> *"When an attacker steals AWS credentials, the first command they run is `aws sts get-caller-identity` to see who they are. The moment they run this command, Thinkst's CloudTrail backend catches the API call."*

---

### 3. Show the Real-Time Alert Received:
Open your email or webhook, or explain the alert contents:
- **Alert Channel**: AWS CloudTrail STS Event
- **Source IP**: Attacker's real public IP address
- **User Agent**: `aws-cli/2.x`
- **Detection Latency**: ~20 seconds
- **False Positive Rate**: **0%** (nobody legitimate should ever touch a decoy key).

---

## Step 5: Executive Conclusion & Mitigations

> **Speaker Script:**  
> *"To summarize the defense-in-depth model:*  
> 1. *Zeek gave us **network-layer visibility** and zero-second alerting on metadata probing.*  
> 2. *Canarytokens gave us **identity-layer tripwires** that alert us during attacker reconnaissance.*  
> 3. *And the root prevention: enforcing **AWS IMDSv2**, which requires a session token and sets a network hop limit of 1, mechanically preventing reverse proxies from forwarding metadata requests.*  
>  
> *This is how modern security operations eliminate 4-month dwell times."*

---

## Quick Reference Cheat Sheet

| Action | One-Liner Command |
|---|---|
| **Interactive Step-by-Step Demo (Recommended)** | `python3 run_interactive_demo.py` |
| **Run Full Zeek Simulation** | `docker run --rm --cap-add=NET_ADMIN -v "$(pwd):/demo" capitalone-zeek-demo /demo/run_simulation.sh` |
| **Run Native macOS Simulation** | `./run_simulation_mac.sh -i` (Interactive) or `./run_simulation_mac.sh` |
| **Check Alert Log** | `zeek-cut ts uid note msg < logs/notice.log` |
| **Check HTTP Log** | `zeek-cut uid method host uri status_code < logs/http.log` |
| **Check Conn Log** | `zeek-cut uid id.orig_h id.resp_h id.resp_p proto < logs/conn.log` |
| **Plant Decoy Key** | `./canary/plant_canary.sh <ACCESS_KEY> <SECRET_KEY>` |
| **Trigger Decoy Key** | `./canary/trigger_canary.sh` |
| **Web Console (Optional)** | `python3 -m http.server 3000 --directory dashboard` &rarr; `http://localhost:3000` |


