# Contributing

`ctx` is an experimental developer preview. Small, focused issues and pull
requests are welcome.

## Development setup

```bash
./scripts/bootstrap
direnv allow  # optional: add .venv/bin to interactive shells
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/ctx validate . --strict
.venv/bin/ctx status . --check
```

The repository's `.python-version` supplies pyenv with Python 3.12.6, while the
ignored `.venv` owns project dependencies. With another version manager, make
sure `python3` is Python 3.11+ or run the bootstrap with an explicit interpreter,
for example `CTX_BOOTSTRAP_PYTHON=/path/to/python3.12 ./scripts/bootstrap`.
Repository automation and agents must use the explicit `.venv/bin/python` and
`.venv/bin/ctx` paths even when direnv is unavailable. The checked-in Codex
Desktop Local Environment runs `./scripts/bootstrap` so every new worktree is
initialized the same way. A first-time bootstrap may download build and runtime
dependencies.

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
