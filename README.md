# MCP Security Runner

Bounded isolated runtime evidence backend for the `agent-security-review` workflow in `AXTRACK/Codex`.

The runner is intentionally not a malware-analysis service and does not issue security verdicts. Runtime execution is manual, bounded, public-data-only, and uses GitHub-hosted ephemeral runners.

Implementation is maintained through pull requests. See the runtime workflow input contract and `result.json` output produced by the harness.
