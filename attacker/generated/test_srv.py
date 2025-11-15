#!/usr/bin/env python3
"""
HTTP test receiver for benign POST data (e.g., webhook testing).
Port: 25566
Receives HTTP POST requests and logs data (two separate endpoints -> two files).
For lawful, authorized testing only.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime
import sys

PORT = 25566  # default port
LOG_FILE = "logs_data_25566.txt"
RECON_LOG_FILE = "recon_data_25566.txt"  # separate file for /recon

class TestRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests and log to different files depending on path."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        # Meta data
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        # Choose log file based on endpoint
        if self.path.rstrip("/") == "/recon":
            target_log = RECON_LOG_FILE
        else:
            # default to /logs (or any other path)
            target_log = LOG_FILE

        # Console output (colored)
        print(f"\n\033[92m[+] [{timestamp}] POST from {client_ip} -> {self.path}\033[0m")
        print(f"    Size: \033[93m{len(post_data)} bytes\033[0m")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'Unknown')}")
        print(f"    \033[96mData:\033[0m")
        if len(post_data) > 500:
            print(f"    {post_data[:500]}...")
            print(f"    \033[91m[TRUNCATED - see log file for full data]\033[0m")
        else:
            print(f"    {post_data}")

        # Append to chosen log file
        with open(target_log, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Client IP: {client_ip}\n")
            f.write(f"Path: {self.path}\n")
            f.write(f"User-Agent: {self.headers.get('User-Agent', 'Unknown')}\n")
            f.write(f"Content-Type: {self.headers.get('Content-Type', 'Unknown')}\n")
            f.write(f"Content-Length: {content_length}\n")
            f.write(f"{'='*70}\n")
            f.write(post_data)
            f.write("\n\n")

        # Respond
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Server', 'Test-Receiver/1.0')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_GET(self):
        """Simple status page."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        print(f"\n\033[93m[*] [{timestamp}] GET {self.path} from {client_ip}\033[0m")

        response = f"""Test Receiver Status
========================
Server Time: {timestamp}
Port: {PORT}
Log File (/logs): {LOG_FILE}
Log File (/recon): {RECON_LOG_FILE}
Status: Active
Client: {client_ip}

POST endpoints:
 - http://localhost:{PORT}/logs
 - http://localhost:{PORT}/recon
"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        # Silence default HTTP logging (we do our own)
        return


def main():
    server_port = PORT
    if len(sys.argv) > 1:
        try:
            server_port = int(sys.argv[1])
        except ValueError:
            print("\033[91mUsage: python3 test_receiver.py [PORT]\033[0m")
            sys.exit(1)

    server_address = ("0.0.0.0", server_port)
    httpd = HTTPServer(server_address, TestRequestHandler)

    print("\033[95m" + "="*70 + "\033[0m")
    print("\033[1;95m       HTTP Test Receiver - Benign POST Logger\033[0m")
    print("\033[95m" + "="*70 + "\033[0m")
    print(f"\n\033[92m[*] Server started successfully!\033[0m")
    print(f"\033[96m[*] Listening on: 0.0.0.0:{server_port}\033[0m")
    print(f"\033[96m[*] Log files: {LOG_FILE}, {RECON_LOG_FILE}\033[0m")
    print(f"\n\033[93m[*] Endpoints:\033[0m")
    print(f"    POST: http://localhost:{server_port}/logs")
    print(f"    POST: http://localhost:{server_port}/recon")
    print(f"    GET:  http://localhost:{server_port}/ (status check)")
    print(f"\n\033[93m[*] Test with curl:\033[0m")
    print(f"    curl -X POST http://localhost:{server_port}/logs -d \"test data\"")
    print(f"    curl -X POST http://localhost:{server_port}/recon -d \"other test data\"")
    print(f"\n\033[91m[*] Press Ctrl+C to stop\033[0m")
    print("\033[95m" + "="*70 + "\033[0m\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n\033[93m[!] Shutting down server...\033[0m")
        httpd.shutdown()
        print("\033[92m[*] Server stopped.\033[0m")
        print(f"\033[96m[*] Logs saved: {LOG_FILE}, {RECON_LOG_FILE}\033[0m")


if __name__ == "__main__":
    main()
