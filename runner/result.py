from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

STATUSES = {"COMPLETED", "TARGET_FAILED", "TIMEOUT", "STOPPED", "RUNTIME_UNSUPPORTED", "HARNESS_ERROR"}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def new_result(request: dict) -> dict:
    return {
        "schema_version": 1,
        "request": {
            "target": request.get("target", {}),
            "question": request.get("question", ""),
            "adapter": request.get("adapter", ""),
            "action_profile": request.get("action_profile", ""),
            "network_mode": request.get("network_mode", ""),
            "evidence": request.get("evidence", []),
        },
        "environment": {},
        "provenance": {
            "requested_ref": request.get("target", {}).get("ref", ""),
            "resolved_commit": "",
            "runtime_version": "",
            "package_manager": "",
            "package_manager_version": "",
            "lockfile_sha256": "",
            "install_mode": "",
        },
        "execution": {"status": "HARNESS_ERROR", "started_at": utc_now(), "ended_at": ""},
        "collectors": [],
        "observations": [],
        "stop_condition_triggered": None,
        "errors": [],
    }

def finish(result: dict, status: str) -> None:
    if status not in STATUSES:
        raise ValueError("Unknown execution status")
    result["execution"]["status"] = status
    result["execution"]["ended_at"] = utc_now()

def write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
