from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

USERS = {
    "1001": {"name": "Alice", "role": "user", "secret": "LAB-ALICE-001"},
    "1002": {"name": "Bob", "role": "user", "secret": "LAB-BOB-002"},
}

class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path)

        if path.path == "/":
            self.respond(200, {
                "application": "AI Red Team Cyber Range",
                "challenge": "Broken Access Control",
                "hint": "Try /record?id=1001"
            })
            return

        if path.path == "/record":
            params = parse_qs(path.query)
            record_id = params.get("id", [""])[0]

            if record_id in USERS:
                # Deliberately vulnerable: no ownership check.
                self.respond(200, USERS[record_id])
            else:
                self.respond(404, {"error": "Record not found"})
            return

        self.respond(404, {"error": "Unknown endpoint"})

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), LabHandler)
    print("AI RED TEAM CYBER RANGE - LOCAL LAB")
    print("Running at http://127.0.0.1:8000")
    print("Press CTRL+C to stop.")
    server.serve_forever()
