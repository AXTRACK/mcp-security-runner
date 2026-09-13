from __future__ import annotations

import argparse
import json
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

TARGET_ROOT = Path("/tmp/mcp-security-target")
TRUSTED_ROOT = Path("/tmp/mcp-security-trusted")
TMP_ROOT = Path("/tmp/mcp-security-fixture-check")


def reset_runtime() -> None:
    shutil.rmtree(TARGET_ROOT, ignore_errors=True)
    shutil.rmtree(TRUSTED_ROOT, ignore_errors=True)
    shutil.rmtree(TMP_ROOT, ignore_errors=True)
    TMP_ROOT.mkdir(parents=True, exist_ok=True)


def request(sha: str, entrypoint: str, timeout: int) -> dict:
    return {
        "schema_version": 1,
        "target": {
            "kind": "git",
            "repository": "AXTRACK/mcp-security-runner",
            "ref": sha,
        },
        "question": "Controlled fixture validation",
        "adapter": "node_stdio",
        "entrypoint": entrypoint,
        "argv": [],
        "action_profile": "mcp_initialize",
        "network_mode": "OPEN",
        "evidence": ["network", "process", "filesystem", "protocol"],
        "credentials": "NONE",
        "timeout_seconds": timeout,
        "stop_conditions": ["output_capture_limit"],
    }


def run_fixture(sha: str, name: str, entrypoint: str, timeout: int) -> dict:
    reset_runtime()
    request_file = TMP_ROOT / f"{name}-request.json"
    result_file = TMP_ROOT / f"{name}-result.json"
    request_file.write_text(json.dumps(request(sha, entrypoint)), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "runner/run_review.py",
            "--request-file",
            str(request_file),
            "--result-file",
            str(result_file),
        ],
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise AssertionError(f"{name}: unexpected harness exit {completed.returncode}")
    result = json.loads(result_file.read_text(encoding="utf-8"))
    try:
        target = pwd.getpwnam("mcp_target")
    except KeyError as exc:
        raise AssertionError("target account was not created") from exc
    lingering = subprocess.run(
        ["pgrep", "-u", str(target.pw_uid)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if lingering.returncode == 0 and lingering.stdout.strip():
        raise AssertionError(f"{name}: target processes survived cleanup: {lingering.stdout.strip()}")
    return result


def observation(result: dict, observation_type: str) -> list[dict]:
    return [item for item in result.get("observations", []) if item.get("type") == observation_type]


def assert_safe(result: dict) -> None:
    assert result["execution"]["status"] == "COMPLETED", result
    protocol = observation(result, "protocol_output")
    assert protocol, result
    server_info = protocol[0]["data"]["initialize_response"]["result"]["serverInfo"]
    assert server_info["name"] == "safe-fixture", result
    filesystem = observation(result, "filesystem_changes")
    assert filesystem and "safe-fixture-output.txt" in filesystem[0]["data"]["paths"], result


def assert_noisy(result: dict) -> None:
    assert result["execution"]["status"] == "COMPLETED", result
    filesystem = observation(result, "filesystem_changes")
    assert filesystem and "noisy-fixture-output.txt" in filesystem[0]["data"]["paths"], result
    assert observation(result, "process_trace"), result
    assert observation(result, "network_trace"), result


def assert_failure(result: dict) -> None:
    assert result["execution"]["status"] == "TIMEOUT", result
    assert any(error.get("phase") == "EXERCISE" for error in result.get("errors", [])), result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    if len(args.sha) != 40:
        raise SystemExit("--sha must be a 40-character commit SHA")

    safe = run_fixture(args.sha, "safe", "fixtures/safe/server.js", 15)
    assert_safe(safe)
    noisy = run_fixture(args.sha, "noisy", "fixtures/noisy/server.js", 15)
    assert_noisy(noisy)
    failure = run_fixture(args.sha, "failure", "fixtures/failure/server.js", 5)
    assert_failure(failure)
    print("Controlled runtime fixtures passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
