#!/usr/bin/env python3
"""
Toy Vulnerable Application simulating WAF/Reverse Proxy SSRF.
Accepts an unvalidated target URL via /fetch?url=<target> and requests it server-side.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request
import sys

class SSRFProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            body = (
                b"<h1>Capital One Vulnerable WAF Simulation</h1>"
                b"<p>Endpoint: <code>/fetch?url=&lt;target&gt;</code></p>"
                b"<p>This service fetches requested URLs server-side without validation (SSRF).</p>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/fetch":
            query = urllib.parse.parse_qs(parsed.query)
            target_url = query.get("url", [None])[0]

            if not target_url:
                body = b"Error: Missing 'url' query parameter. Example: /fetch?url=http://169.254.169.254/latest/meta-data/"
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            try:
                # SSRF Trigger: Vulnerable server-side fetch
                req = urllib.request.Request(target_url, headers={"User-Agent": "WAF-Proxy-Demo/1.0"})
                with urllib.request.urlopen(req, timeout=4) as response:
                    content = response.read()
                    content_type = response.headers.get("Content-Type", "text/plain")
                    self.send_response(response.status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
            except Exception as e:
                err_msg = f"SSRF Request Error fetching {target_url}: {e}\n".encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(err_msg)))
                self.end_headers()
                self.wfile.write(err_msg)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[VULN_APP] {self.client_address[0]} - {args[0]} {args[1]}\n")

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print(f"[*] Starting Vulnerable Application on {host}:{port}...")
    server = HTTPServer((host, port), SSRFProxyHandler)
    server.serve_forever()
