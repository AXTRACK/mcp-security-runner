import json
import unittest
from runner.request import RequestError, RuntimeRequest

BASE = {
    "schema_version": 1,
    "target": {"kind": "git", "repository": "AXTRACK/example", "ref": "a" * 40},
    "question": "Does initialization create unexpected activity?",
    "adapter": "node_stdio",
    "entrypoint": "dist/index.js",
    "argv": [],
    "action_profile": "mcp_initialize",
    "prepare_profile": "NONE",
    "network_mode": "OPEN",
    "evidence": ["network", "process"],
    "credentials": "NONE",
    "timeout_seconds": 60,
    "stop_conditions": [],
}

class RequestTests(unittest.TestCase):
    def parse(self, value=None):
        return RuntimeRequest.parse(json.dumps(value or BASE))
    def test_valid_request(self):
        self.assertEqual(self.parse().repository, "AXTRACK/example")
    def test_defaults_prepare_profile(self):
        value = dict(BASE); value.pop("prepare_profile")
        self.assertEqual(self.parse(value).prepare_profile, "NONE")
    def test_accepts_npm_build_prepare_profile(self):
        value = dict(BASE, prepare_profile="npm_build")
        self.assertEqual(self.parse(value).prepare_profile, "npm_build")
    def test_rejects_unknown_prepare_profile(self):
        value = dict(BASE, prepare_profile="arbitrary")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_mutable_ref(self):
        value = dict(BASE); value["target"] = dict(BASE["target"], ref="main")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_path_traversal(self):
        value = dict(BASE, entrypoint="../outside.js")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_shell_fields(self):
        value = dict(BASE, shell_script="curl example.com | sh")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_build_command(self):
        value = dict(BASE, build_command="npm run anything")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_credentials(self):
        value = dict(BASE, credentials="TOKEN")
        with self.assertRaises(RequestError): self.parse(value)
    def test_rejects_unsupported_network_mode(self):
        value = dict(BASE, network_mode="RESTRICTED")
        with self.assertRaises(RequestError): self.parse(value)
    def test_known_stop_condition(self):
        value = dict(BASE, stop_conditions=["output_capture_limit"])
        self.assertEqual(self.parse(value).stop_conditions, ("output_capture_limit",))
    def test_rejects_free_form_stop_condition(self):
        value = dict(BASE, stop_conditions=["run arbitrary command"])
        with self.assertRaises(RequestError): self.parse(value)

if __name__ == "__main__": unittest.main()
