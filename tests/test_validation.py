import unittest
from runner.run_review import sanitize

class ValidationTests(unittest.TestCase):
    def test_neutralizes_workflow_command_delimiter(self):
        value = sanitize("::error::spoof")
        self.assertNotIn("::", value)
    def test_removes_terminal_control_sequences(self):
        value = sanitize("safe\x1b[31mred")
        self.assertNotIn("\x1b", value)

if __name__ == "__main__": unittest.main()
