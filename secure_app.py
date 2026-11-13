from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

USERS = {
    "1001": {"name": "Alice", "role": "user", "secret": "LAB-ALICE-001"},
    "1002": {"name": "Bob", "role": "user", "secret": "LAB-BOB-002"},
}

class SecureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path)

        if path.path != "/record":
            self.respond(404, {"error": "Not found"})
            return

        params = parse_qs(path.query)
        record_id = params.get("id", [""])[0]

        # Demo-only identity simulation. Not real authentication.
        current_user = self.headers.get("X-Lab-User")

        if current_user not in USERS:
            self.respond(401, {"error": "Authentication required"})
        elif record_id != current_user:
            self.respond(403, {"error": "Access denied"})
        else:
            self.respond(200, USERS[current_user])

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8001), SecureHandler)
    print("SECURE LAB RUNNING: http://127.0.0.1:8001")
    print("Press CTRL+C to stop.")
    server.serve_forever()
