#!/usr/bin/env python3
"""
Simulated AWS EC2 Instance Metadata Service (IMDSv1)
Runs on port 80 and handles metadata requests, including IAM security credentials.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

CREDS_DATA = {
    "Code": "Success",
    "LastUpdated": "2026-09-29T08:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLEWAFROLE12345",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr111111111111111111111111111111111111111111111111111111111111111111111111",
    "Expiration": "2026-12-31T00:00:00Z"
}

S3_EXFIL_DATA = {
    "status": "success",
    "message": "Simulated S3 sync exfiltration completed",
    "bucket": "s3://capitalone-card-applications-production-us-east-1",
    "records_dumped": 106000000,
    "pii_extracted": ["ssn", "name", "address", "credit_score", "account_balances"]
}

class MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path in ("/", "/latest/meta-data", "/latest/meta-data/"):
            self.send_text("iam/\nami-id\nhostname\ninstance-id\nlocal-ipv4\nplacement/\n")
        elif path.startswith("/latest/meta-data/placement/availability-zone"):
            self.send_text("us-east-1a\n")
        elif path in ("/latest/meta-data/iam/security-credentials", "/latest/meta-data/iam/security-credentials/"):
            self.send_text("WAF-Role-CapitalOne-Production\n")
        elif path.startswith("/latest/meta-data/iam/security-credentials/"):
            self.send_json(CREDS_DATA)
        elif "s3" in path or "sync" in path:
            self.send_json(S3_EXFIL_DATA)
        else:
            self.send_text(f"Mock Metadata Item: {path}\n")

    def send_text(self, text, status=200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write(f"[IMDS] {self.client_address[0]} - {args[0]} {args[1]}\n")

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 80
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    print(f"[*] Starting EC2 Mock Metadata Service on {host}:{port}...")
    server = HTTPServer((host, port), MetadataHandler)
    server.serve_forever()
