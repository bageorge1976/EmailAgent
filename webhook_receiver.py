
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        print("Headers:", dict(self.headers))
        try:
            body = json.loads(raw)
        except Exception:
            body = raw.decode("utf-8", "ignore")
        print("Body:", body)
        self.send_response(204)
        self.end_headers()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Webhook receiver on :{port}")
    HTTPServer(("0.0.0.0", port), H).serve_forever()
