import os
from pathlib import Path
import shutil
import unittest

from runner.run_review import TargetFailure, sanitize, target_env, validate_initialize_response


class ValidationTests(unittest.TestCase):
    def test_neutralizes_workflow_command_delimiter(self):
        value = sanitize("::error::spoof")
        self.assertNotIn("::", value)

    def test_removes_terminal_control_sequences(self):
        value = sanitize("safe\x1b[31mred")
        self.assertNotIn("\x1b", value)

    def test_target_environment_is_allowlisted(self):
        environment = target_env()
        self.assertFalse(any(name.startswith("GITHUB_") for name in environment))
        self.assertFalse(any(name.startswith("ACTIONS_") for name in environment))
        self.assertEqual(environment["HOME"], "/tmp/mcp-security-target/home")

    def test_target_path_contains_trusted_node_directory(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        self.assertIn(str(Path(node).parent), target_env()["PATH"].split(os.pathsep))

    def test_accepts_valid_legacy_initialize_result(self):
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "fixture", "version": "1"},
            },
        }
        result = validate_initialize_response(response)
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_rejects_missing_initialize_result_shape(self):
        with self.assertRaises(TargetFailure):
            validate_initialize_response({"jsonrpc": "2.0", "id": 1, "result": {}})

    def test_rejects_wrong_negotiated_protocol_version(self):
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": {"name": "fixture", "version": "1"},
            },
        }
        with self.assertRaises(TargetFailure):
            validate_initialize_response(response)

    def test_rejects_invalid_capabilities_and_server_info(self):
        with self.assertRaises(TargetFailure):
            validate_initialize_response(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": [],
                        "serverInfo": {"name": "fixture", "version": "1"},
                    },
                }
            )
        with self.assertRaises(TargetFailure):
            validate_initialize_response(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "serverInfo": {},
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
