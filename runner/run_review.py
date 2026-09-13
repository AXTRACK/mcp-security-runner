from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import shutil
import subprocess
import threading
import time
from typing import Iterable

try:
    from .request import RequestError, RuntimeRequest
    from .result import finish, new_result, write_result
except ImportError:
    from request import RequestError, RuntimeRequest
    from result import finish, new_result, write_result

TARGET_USER = "mcp_target"
TARGET_ROOT = Path("/tmp/mcp-security-target")
WORKSPACE = TARGET_ROOT / "workspace"
TARGET_HOME = TARGET_ROOT / "home"
TARGET_TMP = TARGET_ROOT / "tmp"
TRUSTED_ROOT = Path("/tmp/mcp-security-trusted")
TRACE_ROOT = TRUSTED_ROOT / "traces"
OUTPUT_LIMIT = 256 * 1024
PHASE_LIMITS = {"ACQUIRE": 120, "INSTALL": 180, "START": 60, "EXERCISE": 120, "STOP": 30}
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x1b]")
SUPPORTED_PROTOCOL_VERSION = "2025-06-18"


class PhaseTimeout(RuntimeError):
    pass


class Unsupported(RuntimeError):
    pass


class TargetFailure(RuntimeError):
    pass


class StopTriggered(RuntimeError):
    def __init__(self, condition: str):
        super().__init__(condition)
        self.condition = condition


def sanitize(text: str, limit: int = 4096) -> str:
    text = CONTROL_RE.sub("?", text)
    text = text.replace("::", ": :")
    return text[:limit]


def validate_initialize_response(response: dict) -> dict:
    result = response.get("result")
    if not isinstance(result, dict):
        raise TargetFailure("MCP initialize result must be an object")
    protocol_version = result.get("protocolVersion")
    if not isinstance(protocol_version, str) or not protocol_version.strip():
        raise TargetFailure("MCP initialize protocolVersion must be a non-empty string")
    if protocol_version != SUPPORTED_PROTOCOL_VERSION:
        raise Unsupported(
            "MCP initialize negotiated unsupported protocolVersion: "
            + sanitize(protocol_version)
        )
    if not isinstance(result.get("capabilities"), dict):
        raise TargetFailure("MCP initialize capabilities must be an object")
    server_info = result.get("serverInfo")
    if not isinstance(server_info, dict):
        raise TargetFailure("MCP initialize serverInfo must be an object")
    if not isinstance(server_info.get("name"), str) or not server_info["name"].strip():
        raise TargetFailure("MCP initialize serverInfo.name must be a non-empty string")
    if not isinstance(server_info.get("version"), str) or not server_info["version"].strip():
        raise TargetFailure("MCP initialize serverInfo.version must be a non-empty string")
    return result


def target_path() -> str:
    directories = []
    for name in ("git", "node", "npm"):
        resolved = shutil.which(name)
        if resolved:
            directories.append(str(Path(resolved).parent))
    directories.extend(["/usr/local/bin", "/usr/bin", "/bin"])
    return ":".join(dict.fromkeys(directories))


def target_env() -> dict[str, str]:
    return {
        "HOME": str(TARGET_HOME),
        "TMPDIR": str(TARGET_TMP),
        "PATH": target_path(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "NPM_CONFIG_CACHE": str(TARGET_HOME / ".npm"),
        "CI": "true",
    }


def ensure_target_user() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Harness must run as root on the disposable runner")
    try:
        pwd.getpwnam(TARGET_USER)
    except KeyError:
        subprocess.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", TARGET_USER],
            check=True,
        )
    pw = pwd.getpwnam(TARGET_USER)
    for path in (TARGET_ROOT, WORKSPACE, TARGET_HOME, TARGET_TMP):
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, pw.pw_uid, pw.pw_gid)
        os.chmod(path, 0o700)
    TRUSTED_ROOT.mkdir(parents=True, exist_ok=True)
    TRACE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(TRUSTED_ROOT, 0, 0)
    os.chown(TRACE_ROOT, 0, 0)
    os.chmod(TRUSTED_ROOT, 0o700)
    os.chmod(TRACE_ROOT, 0o700)


def target_command(command: list[str], phase: str, timeout: int, trace: bool = False) -> list[str]:
    base = ["runuser", "-u", TARGET_USER, "--", "env", "-i"] + [
        f"{key}={value}" for key, value in target_env().items()
    ]
    limited = [
        "prlimit",
        "--nproc=128",
        "--nofile=256",
        "--fsize=67108864",
        f"--cpu={max(5, timeout)}",
        "--",
    ] + command
    full = base + limited
    if trace:
        trace_file = TRACE_ROOT / phase.lower()
        full = [
            "strace",
            "-ff",
            "-qq",
            "-e",
            "trace=network,process,file",
            "-o",
            str(trace_file),
        ] + full
    return full


def terminate_process_group(proc: subprocess.Popen[bytes], graceful: bool = False) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM if graceful else signal.SIGKILL)
    except ProcessLookupError:
        return
    if graceful:
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run_bounded(
    command: list[str],
    phase: str,
    timeout: int,
    trace: bool = False,
    stdin_data: bytes | None = None,
    stop_on_output_limit: bool = False,
) -> tuple[int, str, str]:
    if timeout <= 0:
        raise PhaseTimeout(phase)
    full = target_command(command, phase, timeout, trace)
    proc = subprocess.Popen(
        full,
        cwd=WORKSPACE,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    captured = {"out": bytearray(), "err": bytearray()}
    output_limit_hit = threading.Event()

    def pump(stream, key):
        while True:
            chunk = os.read(stream.fileno(), 8192)
            if not chunk:
                break
            remaining = OUTPUT_LIMIT - len(captured[key])
            if remaining > 0:
                captured[key].extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                output_limit_hit.set()

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    if stdin_data is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin_data)
            proc.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()
    try:
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if stop_on_output_limit and output_limit_hit.is_set():
                terminate_process_group(proc)
                raise StopTriggered("output_capture_limit")
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(full, timeout)
            time.sleep(0.05)
    except subprocess.TimeoutExpired as exc:
        terminate_process_group(proc)
        raise PhaseTimeout(phase) from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
    return (
        proc.returncode,
        captured["out"].decode("utf-8", "replace"),
        captured["err"].decode("utf-8", "replace"),
    )


def run_mcp_initialize(
    command: list[str],
    timeout: int,
    trace: bool,
    stop_on_output_limit: bool,
) -> tuple[str, str, dict]:
    if timeout <= 0:
        raise PhaseTimeout("EXERCISE")

    full = target_command(command, "EXERCISE", timeout, trace)
    proc = subprocess.Popen(
        full,
        cwd=WORKSPACE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    captured = {"out": bytearray(), "err": bytearray()}
    output_limit_hit = threading.Event()
    response_event = threading.Event()
    response_holder: dict[str, dict] = {}

    def append_bounded(key: str, chunk: bytes) -> None:
        remaining = OUTPUT_LIMIT - len(captured[key])
        if remaining > 0:
            captured[key].extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            output_limit_hit.set()

    def inspect_line(line: bytes) -> None:
        if response_event.is_set():
            return
        try:
            message = json.loads(line.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeError):
            return
        if not isinstance(message, dict):
            return
        if message.get("jsonrpc") != "2.0" or message.get("id") != 1:
            return
        if "result" not in message and "error" not in message:
            return
        response_holder["message"] = message
        response_event.set()

    def stdout_pump() -> None:
        pending = bytearray()
        while True:
            chunk = os.read(proc.stdout.fileno(), 8192)
            if not chunk:
                break
            append_bounded("out", chunk)
            pending.extend(chunk)
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                inspect_line(line)
            if len(pending) > OUTPUT_LIMIT:
                output_limit_hit.set()
                pending = pending[-OUTPUT_LIMIT:]
        if pending:
            inspect_line(bytes(pending))

    def stderr_pump() -> None:
        while True:
            chunk = os.read(proc.stderr.fileno(), 8192)
            if not chunk:
                break
            append_bounded("err", chunk)

    threads = [
        threading.Thread(target=stdout_pump, daemon=True),
        threading.Thread(target=stderr_pump, daemon=True),
    ]
    for thread in threads:
        thread.start()

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-security-runner", "version": "1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}

    try:
        if proc.stdin is None:
            raise TargetFailure("Target stdin is unavailable")
        proc.stdin.write((json.dumps(initialize, separators=(",", ":")) + "\n").encode())
        proc.stdin.flush()

        deadline = time.monotonic() + timeout
        while not response_event.is_set():
            if stop_on_output_limit and output_limit_hit.is_set():
                terminate_process_group(proc)
                raise StopTriggered("output_capture_limit")
            if proc.poll() is not None:
                for thread in threads:
                    thread.join(timeout=2)
                out = captured["out"].decode("utf-8", "replace")
                err = captured["err"].decode("utf-8", "replace")
                detail = sanitize(err or out)
                raise TargetFailure(
                    f"Target exited before initialize response with code {proc.returncode}: {detail}"
                )
            if time.monotonic() >= deadline:
                terminate_process_group(proc)
                raise PhaseTimeout("EXERCISE")
            time.sleep(0.02)

        response = response_holder["message"]
        if "error" in response:
            raise TargetFailure(
                "MCP initialize returned JSON-RPC error: "
                + sanitize(json.dumps(response["error"], ensure_ascii=False))
            )
        validate_initialize_response(response)

        try:
            proc.stdin.write((json.dumps(initialized, separators=(",", ":")) + "\n").encode())
            proc.stdin.flush()
            time.sleep(0.05)
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

        terminate_process_group(proc, graceful=True)
        for thread in threads:
            thread.join(timeout=5)
        return (
            captured["out"].decode("utf-8", "replace"),
            captured["err"].decode("utf-8", "replace"),
            response,
        )
    finally:
        terminate_process_group(proc)
        for thread in threads:
            thread.join(timeout=5)


def acquire(req: RuntimeRequest) -> None:
    repo_url = f"https://github.com/{req.repository}.git"
    if any(WORKSPACE.iterdir()):
        raise RuntimeError("Target workspace is not empty")
    rc, _, err = run_bounded(["git", "-c", "core.hooksPath=/dev/null", "init", "."], "ACQUIRE", 30)
    if rc:
        raise TargetFailure(f"git init failed: {sanitize(err)}")
    rc, _, err = run_bounded(
        ["git", "-c", "core.hooksPath=/dev/null", "remote", "add", "origin", repo_url],
        "ACQUIRE",
        10,
    )
    if rc:
        raise TargetFailure(f"git remote add failed: {sanitize(err)}")
    rc, _, err = run_bounded(
        ["git", "-c", "core.hooksPath=/dev/null", "fetch", "--no-tags", "--depth=1", "origin", req.ref],
        "ACQUIRE",
        PHASE_LIMITS["ACQUIRE"],
        trace="network" in req.evidence or "process" in req.evidence,
    )
    if rc:
        raise TargetFailure(f"git fetch failed: {sanitize(err)}")
    rc, _, err = run_bounded(
        ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", "FETCH_HEAD"],
        "ACQUIRE",
        30,
    )
    if rc:
        raise TargetFailure(f"git checkout failed: {sanitize(err)}")
    rc, out, _ = run_bounded(["git", "rev-parse", "HEAD"], "ACQUIRE", 10)
    if rc or out.strip().lower() != req.ref:
        raise TargetFailure("Resolved HEAD does not match requested commit")


def contained_entrypoint(req: RuntimeRequest) -> Path:
    candidate = WORKSPACE / req.entrypoint
    resolved = candidate.resolve(strict=True)
    root = WORKSPACE.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise Unsupported("Entrypoint escapes target workspace") from exc
    if not resolved.is_file():
        raise Unsupported("Entrypoint is not a regular file")
    return resolved


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(root: Path) -> dict[str, tuple[int, int]]:
    result = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [directory for directory in dirs if directory != ".git"]
        for name in files:
            path = Path(current) / name
            try:
                stat = path.lstat()
                rel = str(path.relative_to(root))
                result[rel] = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                continue
    return result


def filesystem_observation(
    before: dict[str, tuple[int, int]],
    after: dict[str, tuple[int, int]],
    phase: str,
) -> dict:
    changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))[:1000]
    return {
        "phase": phase,
        "type": "filesystem_changes",
        "data": {
            "paths": changed,
            "limitation": "workspace metadata only; content not captured; first 1000 changed paths",
        },
    }


def parse_traces(phases: Iterable[str], evidence: set[str]) -> list[dict]:
    observations = []
    for phase in phases:
        for trace in TRACE_ROOT.glob(phase.lower() + "*"):
            try:
                lines = trace.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines[:5000]:
                if "network" in evidence and ("connect(" in line or "sendto(" in line):
                    observations.append(
                        {"phase": phase, "type": "network_trace", "data": {"excerpt": sanitize(line, 1000)}}
                    )
                if "process" in evidence and (
                    "execve(" in line or "clone(" in line or "clone3(" in line or "vfork(" in line
                ):
                    observations.append(
                        {"phase": phase, "type": "process_trace", "data": {"excerpt": sanitize(line, 1000)}}
                    )
                if len(observations) >= 1000:
                    return observations
    return observations


def cleanup_target() -> None:
    try:
        pw = pwd.getpwnam(TARGET_USER)
        subprocess.run(
            ["pkill", "-KILL", "-u", str(pw.pw_uid)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except KeyError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", required=True, type=Path)
    parser.add_argument("--result-file", required=True, type=Path)
    args = parser.parse_args()
    raw = {}
    result = new_result(raw)
    status = "HARNESS_ERROR"
    phases = []
    try:
        request_text = args.request_file.read_text(encoding="utf-8")
        req = RuntimeRequest.parse(request_text)
        raw = req.raw
        result = new_result(raw)
        ensure_target_user()
        result["environment"] = {
            "runner_os": "ubuntu",
            "isolation": "dedicated_unprivileged_user",
            "network_mode": "OPEN",
        }
        requested = set(req.evidence)
        result["collectors"] = [
            {
                "name": "strace",
                "categories": sorted(requested & {"network", "process"}),
                "limitation": "same hosted VM; syscall excerpts are bounded and not tamper-resistant",
            },
            {
                "name": "filesystem_snapshot",
                "categories": sorted(requested & {"filesystem"}),
                "limitation": "workspace metadata only; .git excluded; install and exercise changes are separated",
            },
            {
                "name": "protocol_capture",
                "categories": sorted(requested & {"protocol"}),
                "limitation": "bounded newline-delimited JSON-RPC capture for legacy mcp_initialize only",
            },
        ]
        phases.append("ACQUIRE")
        acquire(req)
        result["provenance"]["resolved_commit"] = req.ref
        lockfile = WORKSPACE / "package-lock.json"
        if not lockfile.is_file():
            raise Unsupported("node_stdio requires package-lock.json")
        result["provenance"]["lockfile_sha256"] = sha256(lockfile)
        after_acquire = snapshot(WORKSPACE) if "filesystem" in requested else {}
        rc, node_version, _ = run_bounded(["node", "--version"], "INSTALL", 10)
        if rc:
            raise Unsupported("Node.js is unavailable")
        rc, npm_version, _ = run_bounded(["npm", "--version"], "INSTALL", 10)
        if rc:
            raise Unsupported("npm is unavailable")
        result["provenance"].update(
            {
                "runtime_version": node_version.strip(),
                "package_manager": "npm",
                "package_manager_version": npm_version.strip(),
                "install_mode": "npm ci",
            }
        )
        phases.append("INSTALL")
        rc, out, err = run_bounded(
            ["npm", "ci", "--no-audit", "--no-fund"],
            "INSTALL",
            PHASE_LIMITS["INSTALL"],
            trace=bool(requested & {"network", "process"}),
        )
        if rc:
            result["errors"].append({"phase": "INSTALL", "message": sanitize(err or out)})
            raise TargetFailure("Target dependency installation failed")
        after_install = snapshot(WORKSPACE) if "filesystem" in requested else {}
        if "filesystem" in requested:
            result["observations"].append(filesystem_observation(after_acquire, after_install, "INSTALL"))
        entrypoint = contained_entrypoint(req)
        phases.extend(["START", "EXERCISE"])
        out, err, response = run_mcp_initialize(
            ["node", str(entrypoint), *req.argv],
            req.timeout_seconds,
            trace=bool(requested & {"network", "process"}),
            stop_on_output_limit="output_capture_limit" in req.stop_conditions,
        )
        if "protocol" in requested:
            result["observations"].append(
                {
                    "phase": "EXERCISE",
                    "type": "protocol_output",
                    "data": {
                        "initialize_response": response,
                        "stdout_excerpt": sanitize(out),
                        "stderr_excerpt": sanitize(err),
                    },
                }
            )
        status = "COMPLETED"
        phases.extend(["STOP", "COLLECT"])
        if "filesystem" in requested:
            after_exercise = snapshot(WORKSPACE)
            result["observations"].append(filesystem_observation(after_install, after_exercise, "EXERCISE"))
        result["observations"].extend(parse_traces(phases, requested))
    except RequestError as exc:
        status = "RUNTIME_UNSUPPORTED"
        result["errors"].append({"phase": "VALIDATE", "message": sanitize(str(exc))})
    except Unsupported as exc:
        status = "RUNTIME_UNSUPPORTED"
        result["errors"].append(
            {"phase": phases[-1] if phases else "VALIDATE", "message": sanitize(str(exc))}
        )
    except StopTriggered as exc:
        status = "STOPPED"
        result["stop_condition_triggered"] = exc.condition
        result["observations"].append(
            {
                "phase": phases[-1] if phases else "UNKNOWN",
                "type": "stop_condition",
                "data": {"condition": exc.condition},
            }
        )
    except PhaseTimeout as exc:
        status = "TIMEOUT"
        result["errors"].append({"phase": str(exc), "message": "Phase timeout"})
    except TargetFailure as exc:
        status = "TARGET_FAILED"
        result["errors"].append(
            {"phase": phases[-1] if phases else "UNKNOWN", "message": sanitize(str(exc))}
        )
    except Exception as exc:
        status = "HARNESS_ERROR"
        result["errors"].append(
            {
                "phase": phases[-1] if phases else "HARNESS",
                "message": sanitize(f"{type(exc).__name__}: {exc}"),
            }
        )
    finally:
        cleanup_target()
        finish(result, status)
        write_result(args.result_file, result)
    return 0 if status in {"COMPLETED", "TARGET_FAILED", "TIMEOUT", "STOPPED", "RUNTIME_UNSUPPORTED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())