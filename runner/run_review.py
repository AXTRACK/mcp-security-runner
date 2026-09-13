from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
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

def target_env() -> dict[str, str]:
    return {
        "HOME": str(TARGET_HOME),
        "TMPDIR": str(TARGET_TMP),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
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
        subprocess.run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", TARGET_USER], check=True)
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

def run_bounded(command: list[str], phase: str, timeout: int, trace: bool = False, stdin_data: bytes | None = None, stop_on_output_limit: bool = False) -> tuple[int, str, str]:
    if timeout <= 0:
        raise PhaseTimeout(phase)
    base = ["runuser", "-u", TARGET_USER, "--", "env", "-i"] + [f"{k}={v}" for k, v in target_env().items()]
    limited = ["prlimit", "--nproc=128", "--nofile=256", "--fsize=67108864", f"--cpu={max(5, timeout)}", "--"] + command
    full = base + limited
    if trace:
        trace_file = TRACE_ROOT / phase.lower()
        full = ["strace", "-ff", "-qq", "-e", "trace=network,process,file", "-o", str(trace_file)] + full
    proc = subprocess.Popen(full, cwd=WORKSPACE, stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    captured = {"out": bytearray(), "err": bytearray()}
    output_limit_hit = threading.Event()
    def pump(stream, key):
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = OUTPUT_LIMIT - len(captured[key])
            if remaining > 0:
                captured[key].extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                output_limit_hit.set()
    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True), threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
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
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=10)
                raise StopTriggered("output_capture_limit")
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(full, timeout)
            time.sleep(0.05)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=10)
        raise PhaseTimeout(phase) from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
    return proc.returncode, captured["out"].decode("utf-8", "replace"), captured["err"].decode("utf-8", "replace")

def acquire(req: RuntimeRequest) -> None:
    repo_url = f"https://github.com/{req.repository}.git"
    if any(WORKSPACE.iterdir()):
        raise RuntimeError("Target workspace is not empty")
    rc, _, err = run_bounded(["git", "-c", "core.hooksPath=/dev/null", "init", "."], "ACQUIRE", 30)
    if rc:
        raise TargetFailure(f"git init failed: {sanitize(err)}")
    rc, _, err = run_bounded(["git", "-c", "core.hooksPath=/dev/null", "remote", "add", "origin", repo_url], "ACQUIRE", 10)
    if rc:
        raise TargetFailure(f"git remote add failed: {sanitize(err)}")
    rc, _, err = run_bounded(["git", "-c", "core.hooksPath=/dev/null", "fetch", "--no-tags", "--depth=1", "origin", req.ref], "ACQUIRE", PHASE_LIMITS["ACQUIRE"], trace="network" in req.evidence or "process" in req.evidence)
    if rc:
        raise TargetFailure(f"git fetch failed: {sanitize(err)}")
    rc, _, err = run_bounded(["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", "FETCH_HEAD"], "ACQUIRE", 30)
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
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            path = Path(current) / name
            try:
                st = path.lstat()
                rel = str(path.relative_to(root))
                result[rel] = (st.st_size, st.st_mtime_ns)
            except OSError:
                continue
    return result

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
                    observations.append({"phase": phase, "type": "network_trace", "data": {"excerpt": sanitize(line, 1000)}})
                if "process" in evidence and ("execve(" in line or "clone(" in line or "clone3(" in line or "vfork(" in line):
                    observations.append({"phase": phase, "type": "process_trace", "data": {"excerpt": sanitize(line, 1000)}})
                if len(observations) >= 1000:
                    return observations
    return observations

def cleanup_target() -> None:
    try:
        pw = pwd.getpwnam(TARGET_USER)
        subprocess.run(["pkill", "-KILL", "-u", str(pw.pw_uid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        result["environment"] = {"runner_os": "ubuntu", "isolation": "dedicated_unprivileged_user", "network_mode": "OPEN"}
        requested = set(req.evidence)
        result["collectors"] = [
            {"name": "strace", "categories": sorted(requested & {"network", "process"}), "limitation": "same hosted VM; syscall excerpts are bounded and not tamper-resistant"},
            {"name": "filesystem_snapshot", "categories": sorted(requested & {"filesystem"}), "limitation": "workspace metadata only; .git excluded"},
            {"name": "protocol_capture", "categories": sorted(requested & {"protocol"}), "limitation": "bounded stdout capture for mcp_initialize only"},
        ]
        phases.append("ACQUIRE")
        acquire(req)
        result["provenance"]["resolved_commit"] = req.ref
        lockfile = WORKSPACE / "package-lock.json"
        if not lockfile.is_file():
            raise Unsupported("node_stdio requires package-lock.json")
        result["provenance"]["lockfile_sha256"] = sha256(lockfile)
        before = snapshot(WORKSPACE) if "filesystem" in requested else {}
        rc, node_version, _ = run_bounded(["node", "--version"], "INSTALL", 10)
        if rc:
            raise Unsupported("Node.js is unavailable")
        rc, npm_version, _ = run_bounded(["npm", "--version"], "INSTALL", 10)
        if rc:
            raise Unsupported("npm is unavailable")
        result["provenance"].update({"runtime_version": node_version.strip(), "package_manager": "npm", "package_manager_version": npm_version.strip(), "install_mode": "npm ci"})
        phases.append("INSTALL")
        rc, out, err = run_bounded(["npm", "ci", "--no-audit", "--no-fund"], "INSTALL", PHASE_LIMITS["INSTALL"], trace=bool(requested & {"network", "process"}))
        if rc:
            result["errors"].append({"phase": "INSTALL", "message": sanitize(err or out)})
            raise TargetFailure("Target dependency installation failed")
        entrypoint = contained_entrypoint(req)
        phases.extend(["START", "EXERCISE"])
        initialize = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-security-runner","version":"1"}}}
        payload = (json.dumps(initialize, separators=(",", ":")) + "\n").encode()
        rc, out, err = run_bounded(["node", str(entrypoint), *req.argv], "EXERCISE", req.timeout_seconds, trace=bool(requested & {"network", "process"}), stdin_data=payload, stop_on_output_limit="output_capture_limit" in req.stop_conditions)
        if "protocol" in requested:
            result["observations"].append({"phase":"EXERCISE","type":"protocol_output","data":{"stdout_excerpt":sanitize(out),"stderr_excerpt":sanitize(err)}})
        if rc:
            result["errors"].append({"phase":"EXERCISE","message":f"Target exited with code {rc}"})
            status = "TARGET_FAILED"
        else:
            status = "COMPLETED"
        phases.extend(["STOP", "COLLECT"])
        if "filesystem" in requested:
            after = snapshot(WORKSPACE)
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))[:1000]
            result["observations"].append({"phase":"COLLECT","type":"filesystem_changes","data":{"paths":changed,"limitation":"workspace metadata only; content not captured"}})
        result["observations"].extend(parse_traces(phases, requested))
    except RequestError as exc:
        status = "RUNTIME_UNSUPPORTED"
        result["errors"].append({"phase":"VALIDATE","message":sanitize(str(exc))})
    except Unsupported as exc:
        status = "RUNTIME_UNSUPPORTED"
        result["errors"].append({"phase":phases[-1] if phases else "VALIDATE","message":sanitize(str(exc))})
    except StopTriggered as exc:
        status = "STOPPED"
        result["stop_condition_triggered"] = exc.condition
        result["observations"].append({"phase": phases[-1] if phases else "UNKNOWN", "type": "stop_condition", "data": {"condition": exc.condition}})
    except PhaseTimeout as exc:
        status = "TIMEOUT"
        result["errors"].append({"phase":str(exc),"message":"Phase timeout"})
    except TargetFailure as exc:
        status = "TARGET_FAILED"
        result["errors"].append({"phase":phases[-1] if phases else "UNKNOWN","message":sanitize(str(exc))})
    except Exception as exc:
        status = "HARNESS_ERROR"
        result["errors"].append({"phase":phases[-1] if phases else "HARNESS","message":sanitize(f"{type(exc).__name__}: {exc}")})
    finally:
        cleanup_target()
        finish(result, status)
        write_result(args.result_file, result)
    return 0 if status in {"COMPLETED", "TARGET_FAILED", "TIMEOUT", "STOPPED", "RUNTIME_UNSUPPORTED"} else 1

if __name__ == "__main__":
    raise SystemExit(main())
