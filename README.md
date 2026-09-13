# MCP Security Runner

A deliberately small runtime-evidence backend for the `agent-security-review` workflow in `AXTRACK/Codex`.

It executes a bounded request on a disposable GitHub-hosted Ubuntu runner and returns factual observations in `result.json`. It **does not** decide whether a target is safe or malicious.

## Security boundary

- Manual `workflow_dispatch` only for target execution.
- Public GitHub repositories at an exact 40-character commit SHA only.
- v1 adapter: `node_stdio` with `package-lock.json` and frozen `npm ci` installation.
- v1 action profile: legacy `mcp_initialize` for protocol version `2025-06-18` only.
- v1 network mode: `OPEN` only.
- Credentials: `NONE`; public/synthetic data only.
- Target acquisition, install hooks, and runtime execute as a dedicated unprivileged OS user.
- Target environment is rebuilt from an allowlist and does not inherit GitHub/Actions credentials.
- The allowlisted PATH includes only trusted runner tool directories required for Git, Node.js, npm, and standard system tools.
- Target workspace is separate from the trusted harness/result paths, and the runtime workflow removes target-user read access to the trusted checkout.
- Entrypoints are resolved and checked for workspace containment before execution.
- Target stdout/stderr is captured as untrusted data, bounded, and sanitized before inclusion in results.
- Process, open-file, file-size, CPU-time, output-volume, phase, and job time limits bound execution.
- `strace` and filesystem snapshots are evidence sensors, not tamper-resistant forensic monitoring.

A clean run means only that no concerning behavior was observed under the tested conditions and collector limitations.

## Request

Run **Actions → Bounded MCP runtime review → Run workflow** and supply one `request_json` value.

`request_json` is transported as data and parsed by the Python harness. It is never used as shell source. Arbitrary command fields are rejected.

v1 supports one executable stop condition: `output_capture_limit`. Any unknown stop condition is rejected as unsupported rather than interpreted as free-form instructions.

For `mcp_initialize`, the harness starts the stdio server, sends `initialize` with protocol version `2025-06-18`, waits for the matching JSON-RPC response, validates the legacy `InitializeResult` shape and negotiated protocol version, sends `notifications/initialized`, and then terminates the disposable target process tree itself. A normal long-lived MCP server is therefore not expected to exit after initialization.

The v1 profile is intentionally legacy-only. Servers that require a newer/stateless MCP protocol revision are outside this action profile and must not be interpreted as unsafe merely because this profile cannot validate them.

## Result

The workflow uploads `mcp-runtime-result/result.json` for three days. Execution states are evidence states only: `COMPLETED`, `TARGET_FAILED`, `TIMEOUT`, `STOPPED`, `RUNTIME_UNSUPPORTED`, or `HARNESS_ERROR`.

`COMPLETED` means the selected bounded action profile completed according to its implemented contract; it is not a security verdict.

The result records request scope, environment/isolation assumptions, exact commit, Node/npm/lockfile provenance, collectors and limitations, bounded observations, stop-condition state, and errors. It never emits a security verdict.

Filesystem observations are phase-separated: install-time changes are reported as `INSTALL`, while target runtime changes are reported as `EXERCISE`. Each list remains bounded and records its limitation.

## Controlled fixtures

CI validates the harness against this repository's exact commit using `fixtures/safe/server.js`, `fixtures/noisy/server.js`, and `fixtures/failure/server.js`.

The fixture job verifies the persistent MCP initialize lifecycle, receipt of `notifications/initialized`, process cleanup, trusted-checkout isolation, phase-separated filesystem observations, process/network traces, and timeout behavior before changes are accepted on `main`.

## Development

Deterministic CI compiles the harness and runs standard-library unit tests. A separate CI job executes only repository-controlled runtime fixtures; it never accepts an arbitrary external target from PR data.

```bash
python3 -m py_compile runner/*.py tests/runtime_fixture_check.py
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Do not add real credentials, private source, customer data, automatic security verdicts, self-hosted runners, or a general arbitrary-command interface.
