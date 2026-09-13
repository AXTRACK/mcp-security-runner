import os
from pathlib import Path
import shutil
import unittest

from runner.run_review import sanitize, target_env


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


if __name__ == "__main__":
    unittest.main()
