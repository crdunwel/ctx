# `ctx` command contract

This document defines the user-facing V1 command grammar. The default workflow
is intentionally two words: `ctx <command>`. Paths and options refine the
operation; they are not required for the common case of working in the current
directory.

The current release is an experimental alpha. The CLI and manifest
schema may change before stable V1. Core commands target Python 3.11–3.14 on
macOS and Linux. Guarded automated retrofit and
reconciliation require POSIX no-follow filesystem primitives; use their
model-free `--prompt` forms where those primitives are unavailable.

## Help and discovery

All of these forms are supported:

```text
ctx help
ctx help <command>
ctx <command> --help
ctx <command> help
```

Help for a command lists every positional argument and named option. Commands
must not hide required workflow behind undocumented subcommands.

## Happy path

```text
ctx demo
ctx retrofit
ctx hydrate
ctx show
ctx status
ctx reconcile
```

- `ctx demo` creates a complete, model-free Permit Board sample with working
  source and tests, root and policy context nodes, canonical project Codex
  hooks, and a fresh lock. It never overwrites an existing path.
- `ctx retrofit` inspects the current project through a guarded local-agent
  adapter, constructs only missing context manifests, strictly validates the
  graph, installs create-only project Codex hooks, writes its initial
  deterministic freshness lock, and registers the project. Existing manifests
  and hook configuration are protected and never overwritten by retrofit.
- `ctx hydrate` emits context for the current directory. It loads the nearest
  node and ancestors, plus a derived routing-only index of the nearest node's
  immediate semantic children. Child content remains dormant. It includes
  another project only when the user names it or supplies `--include`; an
  authored link remains a reference until explicitly selected.
- `ctx show` displays the current directory's inherited context. A path or
  `ctx://` reference selects something else.
- `ctx status` reports current freshness. `--check` is the CI form and fails
  unless every node is valid and fresh.
- `ctx reconcile` handles stale context for the current project through a
  guarded local-agent workflow. Unlike retrofit, reconciliation may propose
  changes to existing manifests, but only through an isolated workspace,
  an allowlisted `.ctx` patch, strict validation, and rollback on failure.

The agent-assisted commands disclose that they invoke the configured agent and
may incur local or provider cost. A `--dry-run` prevents project mutation, not
provider access. Retrofit `--dry-run` saves a content-addressed proposal under
`CTX_HOME`; `--show-plan PLAN_ID` prints its paths and YAML as terminal-safe
JSON, and `--apply PLAN_ID` applies that exact proposal without a second agent
call after rejecting a changed project as stale. Reconcile `--dry-run` validates
a transient proposal and reports only counts and the sanitized agent summary;
it does not save or print exact proposed YAML in this alpha. `--prompt` prints a
standalone agent-neutral prompt and invokes no agent. V1 ships one guarded
automated adapter, `codex`; `--agent` is the stable extension point and rejects
unsupported names instead of silently weakening the sandbox. Other agents use
`--prompt` until they have an equivalent guarded adapter.

Automated agent modes fingerprint every eligible, nonignored regular file, then
make a deterministic bounded selection available to the configured model
through a filtered temporary snapshot. Complete source and governing files are
prioritized fairly across project areas. Non-governing text files over 2 MiB
and large structured data may be rendered as labeled bounded previews; media,
archives, databases, duplicate content, and protected top-level data may be
represented only by path/size/hash metadata or a small representative sample.
Bounded structured-JSON path analysis also completes a few candidate
source/output media pairs when they fit. The ordinary copied-content target is
64 MiB; the absolute whole-snapshot guard is 256 MiB and 50,000 eligible files.
Reconciliation requires affected manifests and their declared artifacts as
complete evidence or fails closed to its manual prompt workflow.

The provider may process files the agent reads. Path/name filtering is not
content-based secret detection, and disabling agent network tools does not make
the model invocation local. Exclude sensitive files and use these modes only
when the configured provider is permitted to process the eligible source.
Inspection omission never removes a file from deterministic freshness. Strict
validation does not scan generated manifest prose for secret values; inspect
`--show-plan` and the resulting `.ctx` diff before committing. Generated
inspection catalogs and previews are temporary adapter data and cannot be
manifest artifacts. The `--prompt` forms invoke no model and remain the
portable handoff.

## Complete command surface

### Construct and maintain

```text
ctx demo [PATH]
ctx retrofit [PATH] [--dry-run | --apply PLAN_ID | --show-plan PLAN_ID | --prompt]
                    [--agent AGENT] [--no-hooks]
ctx reconcile [TARGET] [--dry-run] [--prompt] [--agent AGENT]
                     [--acknowledge REASON]
ctx status [TARGET] [--check] [--json]
ctx validate [PATH] [--strict] [--json]
ctx begin --from PATH --task TEXT [--session ID] [--turn ID] [--json]
ctx reconcile inspect [REFERENCE] --run ID [--json]
ctx reconcile acknowledge REFERENCE --reason REASON --run ID
ctx reconcile complete --run ID
```

The demo path defaults to `./ctx-permit-board-demo` and must not exist or be
nested inside another ctx project. Demo creation is deterministic and invokes
no model; it does not register the sample globally. `PATH` and `TARGET` on
maintenance commands default to the current directory. Retrofit creates missing
manifests only and, by default, installs the canonical project Codex hooks as
part of the same rollback-safe lifecycle. `--no-hooks` is the explicit
agent-neutral opt-out. Prompt, show-plan, and dry-run modes never install hooks;
applying a saved plan does unless `--no-hooks` is supplied. A different or
unsafe existing hooks file is preserved and causes a clean failure instead of
being merged or replaced. Bare `ctx reconcile` is the two-word guarded detached or
human-initiated update path for existing manifests; it is not shorthand for a
run-scoped subcommand. `--acknowledge REASON` is its explicit escape hatch when
every currently affected node has been reviewed and no manifest edit is
warranted. The reason is transient and never copied into the manifest or
deterministic lock.

`ctx begin` captures an immutable pre-edit baseline and returns a stable run ID.
`--session` and `--turn` associate that run with an agent task without changing
the baseline. The run-scoped reconciliation commands require the original
`--run ID`: `inspect` reports bounded evidence, `acknowledge` resolves one
affected reference as implementation-only after review, and `complete` refuses
unresolved or invalid state before atomically refreshing affected lock entries.
An acknowledgement is fingerprint-bound and becomes stale after any later edit.
Run completion also refuses to bless an affected node that was already stale or
context-changed before the baseline; use detached `ctx reconcile` to review that
pre-existing state separately. An agent continuing a run must not invoke `ctx
begin` again.

### Read and hydrate

```text
ctx hydrate [REFERENCE] [--from PATH] [--task TEXT] [--include REF]
            [--budget TOKENS] [--json]
ctx show [REFERENCE] [--json]
ctx search QUERY [--project PROJECT] [--json]
ctx resolve REFERENCE [--json]
ctx graph [REFERENCE] [--depth N] [--json]
```

`REFERENCE` may be a filesystem path, a project ID/name/alias, or a `ctx://`
URI where applicable. Bare `hydrate`, `show`, and `graph` use the current
directory. Search requires a query because an unbounded ambient search is not
useful or safe. JSON hydration uses schema `ctx-hydration/v2`; its
`dormant_scopes` records contain only immediate-child URI, name, and directory,
plus completeness and omitted-count metadata when graph errors or output
bounds prevent a complete routing list. A separate `freshness` object reports
the active node state and whether the complete project is fresh.

### Project universe

```text
ctx register [PATH]
ctx unregister PROJECT
ctx projects [--json]
```

Registration is disposable discovery state under `CTX_HOME`; it never changes
repository meaning. Registration validates strictly and refuses identity or
alias collisions.

### Explicit construction

```text
ctx init [PATH] [--id ID] [--name NAME] [--alias ALIAS]
ctx node [PATH] --id ID --name NAME [--summary TEXT]
```

These commands are for manual or scripted construction. Existing compatibility
syntax `ctx node init ...` remains accepted.

### Diagnostics

```text
ctx doctor [--json]
```

`doctor` checks the Python/PyYAML runtime, registry readability, and optional
guarded Codex adapter. `ctx` itself stays headless, agent-neutral, and
local-first. Retrofit, detached reconciliation, and `doctor` share one Codex
executable resolver: an absolute `CTX_CODEX` override first, then `codex` on
`PATH`, then the standard ChatGPT application bundle on macOS. An invalid
override is an operational error rather than permission to fall back to a
different executable. Human and JSON doctor output report the selected path;
JSON also reports `codex_source` as `environment`, `path`, or `chatgpt-app`.
The selected executable and the `ctx` executable resolved by generated hooks are
part of the local trust boundary.

### Codex hook integration

```text
ctx integrate codex --hooks [--project PATH | --user]
```

This installs the paired `UserPromptSubmit` and `Stop` command hooks for a
selected project or the user. Hook definitions are executable configuration
and require explicit review and trust; project hooks do not run merely because
the file exists. Codex can run multiple matching user and project hooks for one
event, so callers must not assume the ctx hook is exclusive or rely on its
ordering relative to other hooks.

Generated hooks execute `ctx` by name, so the hook process resolves whichever
executable appears first on `PATH`. Before trusting hooks, inspect
`.codex/hooks.json`, run `command -v ctx` and `ctx --version` in the intended
environment, then run `/hooks` in Codex to review and trust the exact hook
definitions. Review hook changes again after pulls or merges. User-wide hooks
affect every workspace.

On `UserPromptSubmit`, the ctx hook begins or reuses the task's stable run,
captures the immutable pre-edit filesystem baseline before work starts, and
returns bounded hydration as additional prompt context. Failure to obtain
optional external context does not block an ordinary local prompt.

On `Stop`, the ctx hook compares the filesystem with that original baseline:

- no relevant change allows Stop immediately;
- fully reviewed changes whose affected manifests were updated or explicitly
  acknowledged are strictly validated and completed automatically before Stop;
- incomplete review blocks Stop exactly once and supplies the original run ID,
  a stable `CTX_RECONCILE_RUN=<run-id>` marker, and the run-scoped inspect,
  acknowledge, and complete commands;
- a second incomplete Stop warns and allows the task to end rather than
  creating a continuation loop.

Hooks perform deterministic detection, hydration, validation, and steering.
They do not autonomously infer whether durable meaning changed and do not edit
source or manifests. A human or the active agent must review evidence and make
any durable manifest edit through normal repository tooling, or explicitly
acknowledge an implementation-only change.

## Compatibility aliases

- `ctx retrofit prompt [PATH]` remains an alias for
  `ctx retrofit [PATH] --prompt`.
- `ctx node init [PATH] ...` remains an alias for `ctx node [PATH] ...`.
- `ctx use REF --for TASK --from PATH` remains an alias for hydration, but new
  documentation uses `ctx hydrate`.
- Run-scoped `ctx reconcile inspect|acknowledge|complete ... --run ID` forms are
  first-class commands. The detached and human default remains bare `ctx
  reconcile`.

## Output and exits

Human output is the default. `--json` writes exactly one JSON document to
stdout and keeps expected diagnostics inside that document. Prompt modes write
only the prompt to stdout. Errors never print tracebacks.

```text
0  success, valid, or fresh
1  invalid input, invalid manifest, stale under --check, or rejected proposal
2  unresolved or ambiguous reference
3  unsafe path, policy denial, or registry collision
4  operational or internal failure
```

Mutation commands are idempotent or fail without partial writes. Read commands
do not mutate repositories. Registry JSON and lock JSON are written atomically.
