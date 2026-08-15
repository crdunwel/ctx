# Security policy

## Supported versions

`ctx` is currently an experimental developer preview. Security fixes are made
on the latest release and the `main` branch; older preview releases are not
maintained separately.

## Reporting a vulnerability

Prefer GitHub's private vulnerability-reporting form:

https://github.com/crdunwel/ctx/security/advisories/new

Do not include exploit details, credentials, private source, or other sensitive
material in a public issue. If private vulnerability reporting is unavailable,
open a minimal issue asking the maintainer to establish a private contact
channel.

Please include the affected version, operating system, reproduction conditions,
impact, and whether the issue involves path containment, symlinks, generated
hooks, agent isolation, registry state, or manifest parsing.

## Agent and data boundary

The portable core does not contain an embedded model or telemetry client.
Agent-assisted `ctx retrofit` and `ctx reconcile`, however, invoke the selected
Codex executable and make eligible files available in a filtered temporary
snapshot. The configured model provider may process files that the agent reads.
Path- and name-based exclusions reduce exposure but are not content-based secret
detection. Do not use automated agent modes on code the configured provider is
not permitted to process, and exclude sensitive files before running them.

Use `--prompt` for a model-free handoff. For review before publication, use
`ctx retrofit --dry-run`, inspect the saved plan with `--show-plan`, and inspect
the resulting `.ctx` diff before committing it.
