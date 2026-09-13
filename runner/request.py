from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import json
import re

_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_ALLOWED_EVIDENCE = {"network", "process", "filesystem", "protocol"}
_FORBIDDEN_KEYS = {"install_command", "startup_command", "test_command", "shell_script"}
_ALLOWED_STOP_CONDITIONS = {"output_capture_limit"}

class RequestError(ValueError):
    pass

@dataclass(frozen=True)
class RuntimeRequest:
    raw: dict
    repository: str
    ref: str
    question: str
    entrypoint: str
    argv: tuple[str, ...]
    evidence: tuple[str, ...]
    timeout_seconds: int
    stop_conditions: tuple[str, ...]

    @classmethod
    def parse(cls, text: str) -> "RuntimeRequest":
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RequestError(f"Invalid JSON: {exc.msg}") from exc
        if not isinstance(raw, dict):
            raise RequestError("Request must be a JSON object")
        if _FORBIDDEN_KEYS.intersection(raw):
            raise RequestError("Arbitrary command fields are forbidden")
        if raw.get("schema_version") != 1:
            raise RequestError("schema_version must be 1")
        target = raw.get("target")
        if not isinstance(target, dict) or target.get("kind") != "git":
            raise RequestError("target.kind must be git")
        repository = target.get("repository", "")
        ref = target.get("ref", "")
        if not isinstance(repository, str) or not _REPO.fullmatch(repository):
            raise RequestError("target.repository must be owner/repository")
        if not isinstance(ref, str) or not _SHA.fullmatch(ref):
            raise RequestError("target.ref must be an exact 40-character commit SHA")
        if raw.get("adapter") != "node_stdio":
            raise RequestError("Only node_stdio is supported in v1")
        if raw.get("action_profile") != "mcp_initialize":
            raise RequestError("Only mcp_initialize is supported in v1")
        if raw.get("network_mode") != "OPEN":
            raise RequestError("Only OPEN network mode is supported in v1")
        if raw.get("credentials") != "NONE":
            raise RequestError("credentials must be NONE in v1")
        question = raw.get("question")
        if not isinstance(question, str) or not question.strip() or len(question) > 1000:
            raise RequestError("question must be a non-empty string up to 1000 characters")
        entrypoint = raw.get("entrypoint")
        if not isinstance(entrypoint, str) or not entrypoint or len(entrypoint) > 500:
            raise RequestError("entrypoint must be a non-empty relative path")
        path = PurePosixPath(entrypoint)
        if path.is_absolute() or ".." in path.parts or entrypoint.startswith("~"):
            raise RequestError("entrypoint must stay within the target workspace")
        argv = raw.get("argv", [])
        if not isinstance(argv, list) or len(argv) > 32 or any(not isinstance(v, str) or len(v) > 1000 for v in argv):
            raise RequestError("argv must be an array of at most 32 bounded strings")
        evidence = raw.get("evidence", [])
        if not isinstance(evidence, list) or not evidence or len(evidence) > len(_ALLOWED_EVIDENCE):
            raise RequestError("evidence must be a non-empty array")
        if any(not isinstance(v, str) or v not in _ALLOWED_EVIDENCE for v in evidence):
            raise RequestError("Unsupported evidence category")
        if len(set(evidence)) != len(evidence):
            raise RequestError("evidence categories must be unique")
        timeout = raw.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 5 or timeout > 120:
            raise RequestError("timeout_seconds must be between 5 and 120")
        stops = raw.get("stop_conditions", [])
        if not isinstance(stops, list) or len(stops) > 16 or any(not isinstance(v, str) or len(v) > 500 for v in stops):
            raise RequestError("stop_conditions must be an array of bounded strings")
        if any(v not in _ALLOWED_STOP_CONDITIONS for v in stops):
            raise RequestError("Unsupported stop condition; v1 supports only output_capture_limit")
        return cls(raw, repository, ref.lower(), question.strip(), entrypoint, tuple(argv), tuple(evidence), timeout, tuple(stops))
