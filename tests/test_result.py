import json
import tempfile
import unittest
from pathlib import Path
from runner.result import finish, new_result, write_result

class ResultTests(unittest.TestCase):
    def test_result_contract(self):
        request = {"target":{"ref":"a"*40},"question":"q","adapter":"node_stdio","action_profile":"mcp_initialize","network_mode":"OPEN","evidence":["process"]}
        result = new_result(request)
        finish(result, "COMPLETED")
        self.assertEqual(result["execution"]["status"], "COMPLETED")
        self.assertIn("provenance", result)
        self.assertNotIn("verdict", result)
    def test_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            result = new_result({})
            finish(result, "RUNTIME_UNSUPPORTED")
            write_result(path, result)
            self.assertEqual(json.loads(path.read_text())["execution"]["status"], "RUNTIME_UNSUPPORTED")

if __name__ == "__main__": unittest.main()
