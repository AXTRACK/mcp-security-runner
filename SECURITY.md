# Security Policy

## Supported versions

`AXTRACK/mcp-security-runner` is maintained as a continuously updated security-analysis harness rather than as a versioned end-user package.

| Version / branch | Supported |
| --- | --- |
| Current `main` | Yes |
| Historical commits, stale branches, and forks | No |

Security fixes are made against the current trusted `main` branch. Reports about behavior that exists only in an old commit, abandoned branch, or fork are normally out of scope unless the same issue is present in current `main`.

## Reporting a vulnerability

Please report security vulnerabilities through GitHub's **private vulnerability reporting** for this repository:

1. Open the repository's **Security and quality** tab.
2. Open **Advisories**.
3. Select **Report a vulnerability**.
4. Submit the report privately.

Do **not** open a public Issue, Discussion, pull request, or public proof-of-concept for a suspected security vulnerability.

A useful report should include:

- a concise summary of the vulnerability;
- the affected workflow, harness component, script, or isolation boundary;
- security impact and realistic attack conditions;
- reproducible steps or a minimal proof of concept when practical;
- whether the issue is known to affect current `main`;
- any mitigation or fix ideas you have already identified.

Do not include real credentials, private repository contents, customer data, production secrets, or unrelated sensitive data in the report. Use synthetic or redacted evidence wherever possible.

## Security-sensitive areas

This repository intentionally executes selected untrusted public MCP source on disposable GitHub-hosted runners under a bounded harness. Reports are especially relevant when they involve:

- bypass of exact commit, repository, adapter, preparation-profile, action-profile, or request validation;
- command, expression, path, argument, or workflow injection through `workflow_dispatch` input or target-controlled data;
- execution outside the intended target workspace or outside the documented command/profile allowlist;
- escape from the dedicated unprivileged target user or other isolation boundaries;
- access by target code to trusted checkout data, workflow state, GitHub credentials, runner credentials, or other secrets;
- unintended privilege escalation, persistence, or host modification beyond the documented runner lifecycle;
- leakage of sensitive data through logs, artifacts, result files, process traces, filesystem observations, or error output;
- tampering with trusted harness code, result generation, or evidence collection;
- a way for target-controlled output to be interpreted as trusted control data;
- network, process, filesystem, resource-limit, or cleanup behavior that materially defeats the documented bounded-execution contract;
- workflow-permission escalation or modification/bypass of the trusted `main` control plane.

A result that merely shows a target failing, timing out, being unsupported by the current action profile, or producing suspicious-looking output is not by itself a vulnerability in this repository. Ordinary test failures, feature requests, compatibility gaps, and non-security reliability problems should be reported through normal GitHub Issues.

## Scope notes

The harness is designed to collect bounded runtime evidence. It does not provide a complete sandbox, a malware verdict, or a guarantee that unobserved behavior is safe.

Reports should focus on weaknesses in this repository's own authorization, workflow, isolation, containment, evidence-integrity, or secret-handling controls rather than on vulnerabilities that exist only in a third-party MCP target.

## Coordinated disclosure

Please keep vulnerability details private while the report is being assessed and, when applicable, while a fix is being prepared. Use the private GitHub advisory thread for follow-up information and coordination.

This repository does not publish a fixed response-time SLA. Maintainer updates and any disclosure timing will be coordinated through the private report.
