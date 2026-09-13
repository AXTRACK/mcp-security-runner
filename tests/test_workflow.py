import unittest
from pathlib import Path

class WorkflowTests(unittest.TestCase):
    def test_request_expression_is_data_only(self):
        text = Path('.github/workflows/runtime-review.yml').read_text(encoding='utf-8')
        expression = '${{ inputs.request_json }}'
        self.assertEqual(text.count(expression), 1)
        self.assertIn(f'REQUEST_JSON: {expression}', text)
    def test_runtime_is_manual_only(self):
        text = Path('.github/workflows/runtime-review.yml').read_text(encoding='utf-8')
        self.assertIn('workflow_dispatch:', text)
        self.assertNotIn('pull_request:', text)
        self.assertNotIn('pull_request_target:', text)
    def test_actions_are_pinned(self):
        text = Path('.github/workflows/runtime-review.yml').read_text(encoding='utf-8')
        self.assertNotIn('actions/checkout@v', text)
        self.assertNotIn('actions/upload-artifact@v', text)
    def test_target_cannot_traverse_runner_home(self):
        text = Path('.github/workflows/runtime-review.yml').read_text(encoding='utf-8')
        self.assertIn('sudo chmod 700 /home/runner', text)

if __name__ == '__main__': unittest.main()
