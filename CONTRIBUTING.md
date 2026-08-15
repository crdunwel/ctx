# Contributing

`ctx` is an experimental developer preview. Small, focused issues and pull
requests are welcome.

## Development setup

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/ctx validate . --strict
.venv/bin/ctx status . --check
```

Keep changes inside the V1 boundaries described in `AGENTS.md`: local-first,
headless, deterministic, and without a daemon, embedded model, telemetry,
SQLite index, embeddings, or RAG.

## Pull requests

- Add focused regression tests for behavior changes.
- Preserve create-only and rollback-safe mutation boundaries.
- Keep JSON output machine-clean and diagnostics deterministic.
- Update durable `.ctx/context.yaml` meaning when a change alters a public
  contract, invariant, decision, pattern, or authoritative artifact.
- Run strict validation and refresh `.ctx/lock.json` through reconciliation.
- Never commit credentials, private source, local registry/run state, virtual
  environments, build output, or generated package metadata.

Security reports should follow `SECURITY.md`, not a public issue.
