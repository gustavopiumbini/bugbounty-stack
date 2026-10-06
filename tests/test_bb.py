import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import bb


class ScopeTests(unittest.TestCase):
    def scope(self, text: str) -> bb.Scope:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with handle:
            handle.write(text)
        self.addCleanup(Path(handle.name).unlink, missing_ok=True)
        return bb.Scope(Path(handle.name))

    def test_exact_and_wildcard(self):
        scope = self.scope("example.com\n*.example.com\n")
        self.assertTrue(scope.allowed("https://example.com/path"))
        self.assertTrue(scope.allowed("api.example.com"))
        self.assertFalse(scope.allowed("notexample.com"))

    def test_wildcard_does_not_include_apex(self):
        scope = self.scope("*.example.com\n")
        self.assertFalse(scope.allowed("example.com"))
        self.assertTrue(scope.allowed("a.example.com"))

    def test_exclusion_wins(self):
        scope = self.scope("*.example.com\n!admin.example.com\n!*.internal.example.com\n")
        self.assertFalse(scope.allowed("admin.example.com"))
        self.assertFalse(scope.allowed("x.internal.example.com"))
        self.assertTrue(scope.allowed("www.example.com"))

    def test_idn_normalization(self):
        self.assertEqual(bb.normalize_host("https://BÜCHER.example./x"), "xn--bcher-kva.example")

    def test_authorization_guard(self):
        with self.assertRaises(ValueError):
            bb.require_authorization(None)
        bb.require_authorization(bb.ACK_TEXT)


class ProbeTests(unittest.TestCase):
    def test_local_fetch_records_hash_without_body(self):
        body = b"local-safe-test"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        config = {
            "user_agent": "bb-test",
            "allow_redirects": False,
            "timeout_seconds": 2,
            "max_response_bytes": 1024,
        }
        result = bb.fetch_url(f"http://127.0.0.1:{server.server_port}/", config)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["bytes_read"], len(body))
        self.assertNotIn("body", result)


if __name__ == "__main__":
    unittest.main()
