"""Local protocol fixture, not a model or representative security benchmark."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


def serve():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable", action="store_true")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            system = request["messages"][0]["content"]
            answer = "4" if "arithmetic" in system else "SAFE"
            if args.vulnerable and "canary" in system:
                answer = "PLX_SYNTHETIC_SECRET_7C91"
            data = json.dumps({"response": answer}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    print(f"Fixture listening on http://127.0.0.1:{args.port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
