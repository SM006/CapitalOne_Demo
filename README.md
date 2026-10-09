# Capital One Breach Defense-in-Depth Demonstration: Zeek + Canarytokens

An end-to-end security engineering lab and case study demonstrating how **passive network security monitoring (Zeek)** and **deception honeypots (Thinkst Canarytokens)** collapse the detection dwell time of the 2019 Capital One SSRF breach from **108 days (~4 months)** down to **0 seconds (instantaneous)**.

---

## Table of Contents
- [1. Executive Summary](#1-executive-summary)
- [2. Attack Chain & Architecture](#2-attack-chain--architecture)
- [3. Repository Structure](#3-repository-structure)
- [4. Quick Start & Lab Execution](#4-quick-start--lab-execution)
  - [Option A: Docker (Recommended)](#option-a-docker-recommended)
  - [Option B: Native macOS](#option-b-native-macos)
  - [Option C: Web Operations Console](#option-c-web-operations-console)
- [5. Part 1: Zeek Network Security Monitoring](#5-part-1-zeek-network-security-monitoring)
  - [SSRF Detection Policy](#ssrf-detection-policy)
  - [Real Captured Telemetry](#real-captured-telemetry)
  - [Cross-Log UID Correlation](#cross-log-uid-correlation)
- [6. Part 2: Canarytokens Active Deception](#6-part-2-canarytokens-active-deception)
  - [Token Generation & Planting](#token-generation--planting)
  - [Adversary Reconnaissance Trigger](#adversary-reconnaissance-trigger)
  - [CloudTrail Ingestion & Alert Verification](#cloudtrail-ingestion--alert-verification)
- [7. Comparative Evaluation & Mitigations](#7-comparative-evaluation--mitigations)
- [8. Cleanup](#8-cleanup)

---

## 1. Executive Summary

In March 2019, an adversary exploited a Server-Side Request Forgery (SSRF) vulnerability in an EC2-hosted ModSecurity Web Application Firewall (WAF) operated by Capital One. By querying the link-local AWS Instance Metadata Service (IMDSv1) at `169.254.169.254`, the attacker retrieved temporary IAM role credentials (`WAF-Role`). Due to excessive IAM permissions, these credentials permitted listing and syncing over 700 S3 buckets, compromising 106 million customer credit card applications.

The intrusion persisted undetected for **108 days**, uncovered only when an external tipster emailed Capital One regarding data posted to a public repository.

This lab proves that deploying two defense-in-depth controls provides instantaneous, multi-layered detection:
1. **Network Layer (Zeek):** Passive link-local traffic inspection detects IMDSv1 queries at wire speed (&lt; 0.01s latency) and unifies transport, application, and alert events under a single connection UID.
2. **Identity Layer (Canarytokens):** Decoy AWS credentials planted in standard credential stores (`~/.aws/credentials`) trip an automated AWS CloudTrail alarm the moment an attacker probes them using the AWS CLI.

---

## 2. Attack Chain & Architecture

```
[ External Attacker ] 
        │
        ▼ 1. Ingress SSRF probe (/fetch?url=http://169.254.169.254/...)
[ ModSecurity WAF Proxy (vuln_app.py:8080) ]
        │
        ▼ 2. Unvalidated GET request to link-local gateway
[ AWS IMDSv1 Endpoint (fake_metadata.py: 169.254.169.254:80) ]
        ├──► Intercepted by Zeek (ssrf_detect.zeek) -> notice.log (T+0.01s)
        │
        ▼ 3. IAM Role Credentials Extracted (WAF-Role)
[ Decoy Storage & Credential Enumeration ]
        ├──► Attacker probes planted honeytoken (~/.aws/credentials)
        └──► CloudTrail STS alert triggered via Thinkst Canarytokens (T+20s)
```

### MITRE ATT&CK Mapping
- **T1190**: Exploit Public-Facing Application (SSRF on WAF)
- **T1552.005**: Unsecured Credentials: Cloud Instance Metadata API
- **T1530**: Data from Cloud Storage Object (S3 Bucket Exfiltration)

---

## 3. Repository Structure

```text
.
├── README.md                # Comprehensive documentation, case study, and run guide
├── run_interactive_demo.py  # Interactive step-by-step CLI demo runner (Presenter Mode)
├── run_simulation_mac.sh    # Native macOS execution script (lo0 alias)
├── run_simulation.sh        # Docker container simulation script
├── Dockerfile               # Turnkey container with Zeek, Python, and AWS CLI

├── docker-compose.yml       # Container composition with NET_ADMIN capability
├── services/                # Simulated target infrastructure
│   ├── vuln_app.py          # Toy HTTP service simulating SSRF-vulnerable WAF proxy
│   └── fake_metadata.py     # Mock AWS IMDSv1 service on 169.254.169.254:80
├── zeek/                    # Network security monitoring policies
│   └── ssrf_detect.zeek     # Custom Zeek detection policy for metadata IP queries
├── docs/                    # Presenter runbooks & manual guides
│   ├── TERMINAL_DEMO_RUNBOOK.md
│   └── STEP_BY_STEP_MANUAL_GUIDE.md
├── canary/                  # Thinkst Canarytoken deception tools
│   ├── plant_canary.sh      # Plant decoy AWS keys into ~/.aws/credentials
│   └── trigger_canary.sh    # Simulate attacker reconnaissance (aws sts)
├── dashboard/               # Minimalist Apple-inspired SOC operations console
│   ├── index.html
│   ├── style.css
│   └── app.js
└── logs/                    # Reference Zeek logs from simulation (conn, http, notice)
```



---

## 4. Quick Start & Lab Execution

### Option A: Interactive Step-by-Step CLI (Presenter Mode)
Walks through the demo step-by-step with concise technical descriptions, exact command previews, and waits for you to press **[ENTER]** before executing each command:

```bash
# Run the interactive presenter runner:
python3 run_interactive_demo.py
```
*Keyboard controls:*
- Press **[ENTER]** to execute the step
- Type `s` and press **[ENTER]** to skip a step
- Type `q` and press **[ENTER]** to exit and auto-cleanup background processes

---

### Option B: Native macOS

If you prefer running directly on macOS:

```bash
# 1. Install Zeek (Homebrew)
brew install zeek

# 2. Run the macOS simulation script (interactive or non-interactive)
./run_simulation_mac.sh -i   # Interactive mode (pauses on Enter)
./run_simulation_mac.sh      # Automated non-stop mode
```

---

### Option C: Docker (Headless Container)
Runs in an isolated container without requiring root configuration or tool installation on your host machine:

```bash
# Build and run the simulation in one command:
docker run --rm --cap-add=NET_ADMIN -v "$(pwd):/demo" capitalone-zeek-demo /demo/run_simulation.sh
```

---

### Option D: Web Operations Console


---

### Option C: Web Operations Console

An interactive, Apple-inspired Security Operations Console is included in `dashboard/`:

```bash
# Start local dashboard server:
python3 -m http.server 3000 --directory dashboard
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser to inspect:
- Interactive attack topology with live packet flow animation.
- Tabular log viewer (`notice.log`, `http.log`, `conn.log`) with live text search.
- One-click connection UID cross-highlighting across network layers.
- Interactive Canarytoken probe simulator with raw CloudTrail JSON rendering.

---

## 5. Part 1: Zeek Network Security Monitoring

### SSRF Detection Policy (`ssrf_detect.zeek`)

```zeek
module SSRF;

export {
    redef enum Notice::Type += {
        Metadata_Access
    };
}

event http_request(c: connection, method: string, original_URI: string,
                    unescaped_URI: string, version: string)
    {
    if ( c$id$resp_h == 169.254.169.254 )
        {
        NOTICE([$note=SSRF::Metadata_Access,
                $msg=fmt("Possible SSRF: AWS EC2 metadata service accessed by %s (Requested URI: %s)",
                         c$id$orig_h, original_URI),
                $conn=c]);
        }
    }
```

### Real Captured Telemetry

#### 1. Ingress & Internal Requests (`http.log`)
```text
#fields ts                  uid                host             uri                                                                         status_code
1790672629.439358          CINDfJ27E2fRaKJzVf 127.0.0.1:8080   /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ 200
1790672629.461230          CjbXsRqWg8nivYnui  169.254.169.254  /latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production   200
1790672629.479822          C1AKQ61lPHgHJ1WiQg 127.0.0.1:8080   /fetch?url=http://169.254.169.254/mock-s3-bucket/sync                       200
1790672629.480405          CCHznt2GFsuQhsfvsk 169.254.169.254  /mock-s3-bucket/sync                                                        200
```

#### 2. Real-Time Detection Notice (`notice.log`)
```text
#fields ts                  uid                note                   msg
1790672629.461230          CjbXsRqWg8nivYnui  SSRF::Metadata_Access  Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254
1790672629.480405          CCHznt2GFsuQhsfvsk SSRF::Metadata_Access  Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254
```

### Cross-Log UID Correlation

Every connection in Zeek receives a globally unique session identifier (`uid`). In our simulation, UID **`CjbXsRqWg8nivYnui`** binds all three layers together deterministically:

```text
Correlation Key (UID): CjbXsRqWg8nivYnui
  ├── [notice.log] Alert: SSRF::Metadata_Access (Dest: 169.254.169.254)
  ├── [http.log]   Payload: GET /latest/meta-data/iam/security-credentials/... (Status: 200 OK)
  └── [conn.log]   Transport: 169.254.169.254:46748 -> 169.254.169.254:80 (TCP, 191 bytes sent, 478 bytes recv)
```

> **Incident Response Takeaway:**  
> In the 2019 incident, Capital One had to reconstruct events manually months later across disconnected VPC flow logs, web server logs, and CloudTrail dumps. Zeek produces this correlation automatically and instantaneously at capture time.

---

## 6. Part 2: Canarytokens Active Deception

### Token Generation & Planting

1. Visit [canarytokens.org](https://canarytokens.org) and generate an **AWS Keys** token.
2. Provide your alert email or webhook and label it (e.g. `Capital One WAF EC2 Decoy`).
3. Plant the decoy credentials on the host:

```bash
./plant_canary.sh <CANARY_ACCESS_KEY_ID> <CANARY_SECRET_ACCESS_KEY>
```

Planted artifact (`~/.aws/credentials`):
```ini
[canary]
aws_access_key_id = AKIATU7L4S6WVXD4O77Z
aws_secret_access_key = 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
```

### Adversary Reconnaissance Trigger

Adversaries discovering AWS credentials universally run `sts:GetCallerIdentity` to evaluate privileges:

```bash
./trigger_canary.sh
# Under the hood: aws sts get-caller-identity --profile canary --region us-east-1
```

Terminal Output:
```json
{
    "UserId": "AIDATU7L4S6W5LRX4CBJF",
    "Account": "251213420461",
    "Arn": "arn:aws:iam::251213420461:user/azqjoxxwnbghiqrlgpsilbuqdrvuarunrsbsgtbgvlitxufczq"
}
```

### CloudTrail Ingestion & Alert Verification

The API call hits Thinkst's monitored AWS honeypot account (`251213420461`), generating an immediate CloudTrail event and dispatching an email/webhook notification:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDATU7L4S6W5LRX4CBJF",
    "arn": "arn:aws:iam::251213420461:user/azqjoxxwnbghiqrlgpsilbuqdrvuarunrsbsgtbgvlitxufczq",
    "accountId": "251213420461",
    "accessKeyId": "AKIATU7L4S6WVXD4O77Z"
  },
  "eventTime": "2026-09-29T09:18:45Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "GetCallerIdentity",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.42",
  "userAgent": "aws-cli/2.15.15 Python/3.11.6 Darwin/23.4.0",
  "eventType": "AwsApiCall"
}
```

---

## 7. Comparative Evaluation & Mitigations

| Evaluation Metric | 2019 Capital One Incident | Zeek Network Monitoring | Canarytokens Honeykeys |
|---|---|---|---|
| **Mean Time to Detect (MTTD)** | 108 Days (4 Months) | **&lt; 0.01 Seconds** | **15–30 Seconds** |
| **Detection Channel** | External Tipster (GitHub dump) | Passive L4/L7 NIDS Rule | CloudTrail STS API Hook |
| **Forensic Correlation Effort** | High: Manual multi-month effort | **Zero: Automated via UID** | **Zero: Pre-attributed decoy key** |
| **False Positive Probability** | Not applicable | Low (target link-local IP) | **0% (Pure honeytoken)** |
| **Architectural Remediation** | None in place | Egress link-local controls | Least privilege IAM scoping |

### Root Cause Prevention: IMDSv2
While Zeek and Canarytokens provide immediate detection, the fundamental architectural prevention is enforcing **IMDSv2**:
- Requires a session token via `PUT /latest/api/token` with an explicit TTL (`X-aws-ec2-metadata-token-ttl-seconds`).
- Subsequent metadata queries require the session token header (`X-aws-ec2-metadata-token`).
- Default hop limit is set to `1`, preventing reverse proxies or SSRF endpoints from forwarding metadata requests off the local host.

---

## 8. Cleanup

```bash
# Clean up Docker resources
docker rm -f zeek-capitalone-lab 2>/dev/null || true

# Remove loopback alias (if run natively on macOS)
sudo ifconfig lo0 -alias 169.254.169.254 2>/dev/null || true
```
