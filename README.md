# MCP Security Runner

A deliberately small runtime-evidence backend for the `agent-security-review` workflow in `AXTRACK/Codex`.

It executes a bounded request on a disposable GitHub-hosted Ubuntu runner and returns factual observations in `result.json`. It **does not** decide whether a target is safe or malicious.

## Security boundary

- Manual `workflow_dispatch` only for target execution.
- Public GitHub repositories at an exact 40-character commit SHA only.
- v1 adapter: `node_stdio` with `package-lock.json` and frozen `npm ci` installation.
- v1 action profile: `mcp_initialize`.
- v1 network mode: `OPEN` only.
- Credentials: `NONE`; public/synthetic data only.
- Target acquisition, install hooks, and runtime execute as a dedicated unprivileged OS user.
- Target environment is rebuilt from an allowlist and does not inherit GitHub/Actions credentials.
- Target workspace is separate from the trusted harness/result paths.
- Entrypoints are resolved and checked for workspace containment before execution.
- Target stdout/stderr is captured as untrusted data, bounded, and sanitized before inclusion in results.
- Process, open-file, file-size, CPU-time, output-volume, phase, and job time limits bound execution.
- `strace` and filesystem snapshots are evidence sensors, not tamper-resistant forensic monitoring.

A clean run means only that no concerning behavior was observed under the tested conditions and collector limitations.

## Request

Run **Actions → Bounded MCP runtime review → Run workflow** and supply one `request_json` value.

`request_json` is transported as data and parsed by the Python harness. It is never used as shell source. Arbitrary command fields are rejected.

v1 supports one executable stop condition: `output_capture_limit`. Any unknown stop condition is rejected as unsupported rather than interpreted as free-form instructions.

## Result

The workflow uploads `mcp-runtime-result/result.json` for three days. Execution states are evidence states only: `COMPLETED`, `TARGET_FAILED`, `TIMEOUT`, `STOPPED`, `RUNTIME_UNSUPPORTED`, or `HARNESS_ERROR`.

The result records request scope, environment/isolation assumptions, exact commit, Node/npm/lockfile provenance, collectors and limitations, bounded observations, stop-condition state, and errors. It never emits a security verdict.

## Controlled fixtures

Before using third-party runtime output as security evidence, validate the harness against this repository's exact merged commit using `fixtures/safe/server.js`, `fixtures/noisy/server.js`, and `fixtures/failure/server.js`. All three use the repository-root `package-lock.json`.

## Development

Deterministic CI compiles the harness and runs standard-library unit tests. It never dispatches arbitrary third-party targets.

```bash
python3 -m py_compile runner/*.py
python3 -m unittest discover -s tests -v
```

Do not add real credentials, private source, customer data, automatic security verdicts, self-hosted runners, or a general arbitrary-command interface.
