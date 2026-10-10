"""
Local Web GUI Server for PassGuard Password Strength Auditor.
Built purely with Python's standard library (http.server, json, urllib, webbrowser).
Zero external pip dependencies required.
Strictly local-only (binds to 127.0.0.1) with volatile-memory evaluation.
"""

import sys
import os
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.checker import PasswordStrengthChecker
from src.generator import generate_random_password, generate_passphrase, estimate_crack_time

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
checker = PasswordStrengthChecker()


class PasswordAuditorHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            index_path = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        elif path == "/api/generate":
            params = parse_qs(parsed.query)
            gen_type = params.get("type", ["random"])[0]

            if gen_type == "passphrase":
                pwd = generate_passphrase(word_count=4, separator="-", capitalize=True, include_number=True)
            else:
                pwd = generate_random_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True)

            payload = json.dumps({"password": pwd}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/evaluate":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                data = {}

            pwd = data.get("password", "")
            res = checker.evaluate(pwd)
            res_dict = res.to_dict()

            # Attach crack time estimate and character counts
            res_dict["crack_time"] = estimate_crack_time(res.entropy.total_shannon_entropy)
            res_dict["unique_count"] = res.variety.unique_char_count
            res_dict["counts"] = {
                "lower": res.variety.lowercase_count,
                "upper": res.variety.uppercase_count,
                "digit": res.variety.digit_count,
                "symbol": res.variety.symbol_count,
            }

            payload = json.dumps(res_dict).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_error(404, "Endpoint Not Found")

    def log_message(self, format, *args):
        # Silence verbose request logs to keep terminal clean and prevent password leakage in logs
        return


def run_web_server(port: int = 8080, open_browser: bool = True):
    server_address = ("127.0.0.1", port)
    try:
        httpd = HTTPServer(server_address, PasswordAuditorHTTPHandler)
    except OSError:
        # If port 8080 is taken, try port 8081
        port = 8081
        server_address = ("127.0.0.1", port)
        httpd = HTTPServer(server_address, PasswordAuditorHTTPHandler)

    url = f"http://127.0.0.1:{port}"
    print("=" * 65)
    print(" PassGuard Web GUI Dashboard Running!")
    print(f" URL: {url}")
    print(" Zero Storage • Zero Remote Transmission • Volatile Memory Only")
    print(" Press Ctrl+C in terminal to stop.")
    print("=" * 65)

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb server stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_web_server()
