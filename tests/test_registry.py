import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from tailnet_agents.registry import Registry, make_handler


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.registry = Registry({"a": "a" * 32, "b": "b" * 32}, lambda: self.now)
        self.record = {"id": "coder", "endpoint": "https://coder.example.ts.net/a2a/v1",
                       "skills": ["coding"], "ttl_seconds": 30}

    def test_lease_and_refresh(self):
        self.registry.register("a", self.record)
        self.assertEqual(len(self.registry.discover("coding")), 1)
        self.assertEqual(self.registry.discover("search"), [])
        self.now = 30
        self.assertEqual(self.registry.discover(), [])
        self.registry.register("a", self.record)
        self.assertEqual(len(self.registry.discover()), 1)

    def test_identity_cannot_be_overwritten_even_after_expiry(self):
        self.registry.register("a", self.record)
        self.now = 100
        with self.assertRaises(PermissionError):
            self.registry.register("b", self.record)

    def test_invalid_metadata(self):
        for patch in ({"endpoint": "file:///etc/passwd"}, {"skills": "coding"},
                      {"ttl_seconds": True}, {"id": "../coder"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.registry.register("a", self.record | patch)

    def test_http_auth_and_discovery(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.registry))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(HTTPError) as failure:
                urlopen(base + "/v1/agents")
            self.assertEqual(failure.exception.code, 403)
            headers = {"Authorization": "Bearer " + "a" * 32, "Content-Type": "application/json"}
            request = Request(base + "/v1/agents", json.dumps(self.record).encode(), headers)
            with urlopen(request) as response:
                self.assertEqual(response.status, 200)
            with urlopen(Request(base + "/v1/agents?skill=coding", headers=headers)) as response:
                self.assertEqual(json.load(response)["agents"][0]["id"], "coder")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
