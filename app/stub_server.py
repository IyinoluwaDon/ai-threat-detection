"""Tiny target server that writes Nginx-combined-format access logs."""
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "logs/access.log"


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        ts = time.strftime("%d/%b/%Y:%H:%M:%S %z")
        ua = self.headers.get("User-Agent", "-")
        ref = self.headers.get("Referer", "-")
        line = (f'{self.client_address[0]} - - [{ts}] '
                f'"{self.command} {self.path} {self.request_version}" '
                f'200 {len(body)} "{ref}" "{ua}"\n')
        with open(LOG, "a") as f:
            f.write(line)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    open(LOG, "a").close()
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
