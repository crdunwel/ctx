# `ctx` command contract

This document defines the user-facing V1 command grammar. The default workflow
is intentionally two words: `ctx <command>`. Paths and options refine the
operation; they are not required for the common case of working in the current
directory.

The current release is an experimental alpha. The CLI and manifest
schema may change before stable V1. Core commands target Python 3.11–3.14 on
macOS and Linux. Guarded automated retrofit, reconciliation, and instruction
review require POSIX no-follow filesystem primitives. Retrofit and reconcile
retain portable model-free prompt forms; `ctx agents prompt` audits the exact
guarded prompt and therefore uses the same bounded-snapshot prerequisites as
`ctx agents review`.

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
ctx agents review
```

For an immediate, model-free proof that an existing graph is useful, run:

```text
ctx hydrate --task "Orient me to this project and identify the best next scope"
```

This prints the same bounded packet an integrated agent receives. It requires
no Codex hook support and works on every surface where the agent can run a CLI.

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
  authored link remains a reference until explicitly selected. An external
  filesystem include must belong to a registered checkout and inherits that
  registry entry's trust and reuse policy.
- `ctx show` displays the current directory's inherited context. A path or
  `ctx://` reference selects something else.
- `ctx status` reports current freshness. `--check` is the CI form and fails
  unless every node is valid and fresh.
- `ctx reconcile` handles stale context for the current project through a
  guarded local-agent workflow. Unlike retrofit, reconciliation may propose
  changes to existing manifests, but only through an isolated workspace,
  an allowlisted `.ctx` patch, strict validation, and rollback on failure.
- `ctx agents review` asks Codex whether the nearest applicable `AGENTS.md`
  needs a minimal durable operational update. It saves an exact plan and does
  not modify the project; `show-plan` and `apply` keep review and publication
  separate.

The agent-assisted commands disclose that they invoke the configured agent and
may incur local or provider cost. A `--dry-run` prevents project mutation, not
provider access. Retrofit `--dry-run` saves a content-addressed proposal under
`CTX_HOME`; `--show-plan PLAN_ID` prints its paths and YAML as terminal-safe
JSON, and `--apply PLAN_ID` applies that exact proposal without a second agent
call after rejecting a changed project as stale. The saved plan also shows the
transient structural-area dispositions and evidence-backed conflict review;
unresolved areas or review-required conflicts block application. Reconcile `--dry-run` validates
a transient proposal and reports only counts and the sanitized agent summary;
it does not save or print exact proposed YAML in this alpha. `--prompt` prints a
standalone agent-neutral prompt and invokes no agent. V1 ships one guarded
automated adapter, `codex`; `--agent` is the stable extension point and rejects
unsupported names instead of silently weakening the sandbox. Other agents use
`--prompt` until they have an equivalent guarded adapter.

Instruction review has its own explicit plan workflow. `ctx agents review`
invokes the configured agent but never writes the repository. `ctx agents
show-plan PLAN_ID` prints the complete proposed `AGENTS.md` bytes and bound
evidence as terminal-safe JSON. `ctx agents apply PLAN_ID` invokes no model,
revalidates the saved selector, evidence, project, and destination baseline,
then atomically writes exactly those bytes. None of these commands modifies the
Git index or creates a commit. `ctx agents prompt` builds the same bounded
selection and prints the exact adapter prompt without invoking a model, saving
a plan, or changing project files.

Automated agent modes fingerprint every eligible, nonignored regular file, then
make a deterministic bounded selection available to the configured model
through a filtered temporary snapshot. Retrofit prioritizes complete source and
governing files fairly across bounded hierarchical project areas. Reconciliation
copies only affected-node ownership, declared evidence, and mandatory context
while retaining the complete fingerprint for race detection. With a usable Git
`HEAD`, it also creates bounded supplemental `HEAD`-to-working-tree change
evidence for already-copied eligible affected files. That evidence combines
staged and unstaged changes, lists bounded untracked additions, redacts
historical-only deleted line bodies, and never replaces inspection of current
source. Non-governing text files over 2 MiB
and large structured data may be rendered as labeled bounded previews; media,
archives, databases, duplicate content, and protected top-level data may be
represented only by path/size/hash metadata or a small representative sample.
Bounded structured-JSON path analysis also completes a few candidate
source/output media pairs when they fit. The ordinary copied-content target is
64 MiB; the absolute whole-snapshot guard is 256 MiB and 50,000 eligible files.
Reconciliation requires affected manifests and their declared artifacts as
complete evidence or fails closed to its manual prompt workflow.

Instruction review selects one applicable `AGENTS.md`, the bounded Git change,
current source around that change, applicable instruction topology, validated
context manifests, relevant declared artifacts, and repository build/test/CI
evidence. Existing instructions and manifests are untrusted review evidence;
they cannot broaden the prompt or authorize execution. The Codex adapter is
read-only, has no network or subagents, and its prompt forbids executing
project commands.

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
                    [--review] [--agent AGENT] [--no-hooks]
ctx reconcile [TARGET] [--dry-run] [--prompt] [--agent AGENT]
                     [--acknowledge REASON]
ctx status [TARGET] [--check] [--json]
ctx validate [PATH] [--strict] [--json]
ctx begin --from PATH --task TEXT [--session ID] [--turn ID] [--json]
ctx reconcile inspect [REFERENCE] --run ID [--json]
ctx reconcile acknowledge REFERENCE --reason REASON --run ID
ctx reconcile complete --run ID
ctx agents review [PATH] [--staged | --since REF | --run ID] [--agent AGENT]
ctx agents prompt [PATH] [--staged | --since REF | --run ID]
ctx agents show-plan PLAN_ID
ctx agents apply PLAN_ID
ctx integrate git --hooks [--project PATH] [--block]
```

The demo path defaults to `./ctx-permit-board-demo` and must not exist or be
nested inside another ctx project. Demo creation is deterministic and invokes
no model; it does not register the sample globally. `PATH` and `TARGET` on
maintenance commands default to the current directory. Retrofit creates missing
manifests only and, by default, enables canonical Codex hooks as part of the
same rollback-safe lifecycle. It reuses an exact canonical user hook instead of
creating a duplicate project hook; otherwise it installs the project hook.
`--no-hooks` is the explicit agent-neutral opt-out. Prompt, show-plan, and dry-run modes never install hooks;
applying a saved plan does unless `--no-hooks` is supplied. A different or
unsafe existing hooks file is preserved and causes a clean failure instead of
being merged or replaced. `ctx retrofit review [PATH]` forces a dry-run against
an already-fresh graph so missing semantic scopes can be proposed without
overwriting existing manifests; review and apply its saved plan separately.
Agent-backed runs print concise stages and a ten-second elapsed heartbeat on
stderr. Raw Codex transcript output is suppressed; `Ctrl-C` terminates and
reaps the child before any proposal is published, and failures expose only a
bounded relevant diagnostic.
Bare `ctx reconcile` is the two-word guarded detached or
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

### Guarded `AGENTS.md` review

`AGENTS.md` is governing operational input for future agents: supported
runtimes, bootstrap and verification commands, generated-file ownership,
directory-specific workflows, and durable safety boundaries belong there.
`.ctx/context.yaml` is untrusted semantic project data: it records purpose,
canonical artifacts, invariants, decisions, reusable patterns, and context
routing. A manifest may route an agent to an `AGENTS.md` artifact, but semantic
context never overrides governing instructions. Do not duplicate general
architecture prose between the two files.

`PATH` selects the nearest applicable instruction scope. V1 reviews exactly one
destination: it may update the nearest existing `AGENTS.md`, return `no-op` or
`review-required`, or create a missing root `AGENTS.md`. It never creates,
moves, or deletes a nested instruction file. Existing nested files are supplied
as precedence context so the proposal does not duplicate or weaken their
guidance.

Change selectors are mutually exclusive:

- no selector compares `HEAD` with the current working tree, including staged,
  unstaged, and nonignored untracked paths in the applicable scope;
- `--staged` compares `HEAD` with the index and requires a Git `HEAD`, no
  unstaged tracked changes, and no nonignored untracked files;
- `--since REF` resolves `REF` to a commit and compares it through the current
  working tree;
- `--run ID` uses only paths safely attributable to the immutable ctx run
  baseline and fails closed when files were already dirty or attribution is
  unavailable.

Incremental review of an existing instruction file requires a Git `HEAD`. The
only no-`HEAD` exception is synthesizing a missing root `AGENTS.md` from the
bounded current snapshot.

Review strictly validates the ctx graph, inventories a filtered snapshot, and
supplies Codex with bounded change routing plus current authoritative source.
Deleted historical line bodies are redacted. Codex can propose only complete
bytes for the one allowed file and must cite copied evidence. A missing or
contradictory corpus, unsafe target, project race, unsupported adapter, or need
for a new nested scope fails closed or produces `review-required`.

The exact staged-commit workflow is:

```text
git add <changed-source-paths>
ctx agents review --staged
ctx agents show-plan PLAN_ID
ctx agents apply PLAN_ID
git diff -- AGENTS.md
git add AGENTS.md
ctx reconcile
git diff -- .ctx
git add .ctx
ctx status --check
git commit
```

Run `ctx agents prompt --staged` before review to print the exact prompt ctx
would pass to Codex. Prompt and show-plan are model-free and mutation-free.
Review is the only step here that invokes Codex, and it saves its
content-addressed plan under `CTX_HOME` without writing the project. Apply
rejects a stale plan, a changed selector or evidence set, a changed destination,
invalid context, and `review-required`; it does not invoke a second model call.
No agents command stages, commits, pushes, or runs automatically from the Git
hook. After applying and staging operational guidance, `ctx reconcile`
separately updates or acknowledges semantic context and refreshes the lock.

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
ctx doctor [PATH] [--json]
```

`doctor` checks the Python/PyYAML runtime, registry readability, and optional
guarded Codex adapter. From a ctx project it also safely compares project and
user hooks with the canonical definition, warns when both scopes may execute,
and reports that host trust is not inspectable. It never parses or follows an
unsafe hook file. `ctx` itself stays headless, agent-neutral, and local-first.
Retrofit, detached reconciliation, and `doctor` share one Codex
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

`ctx` does not install a `/ctx` slash command or add an item to the Codex
command palette. This integration installs lifecycle command hooks only.

Generated hooks execute `ctx` by name, so the hook process resolves whichever
executable appears first on `PATH`. Before trusting hooks, inspect
`.codex/hooks.json`, run `command -v ctx` and `ctx --version` in the intended
environment, then start the Codex CLI/TUI in the project and run `/hooks` to
review and trust the exact hook definitions. Review hook changes again after
pulls or merges. User-wide hooks affect every workspace.

Choose user-wide or project ctx hooks, not both. Codex launches matching hooks
from multiple files concurrently; identical trusted definitions in
`~/.codex/hooks.json` and `<repo>/.codex/hooks.json` therefore run hydration and
stop checks twice. Project hooks are portable and versioned with one repository.
For one-time setup across every ctx project, install the user hook once. Bare
retrofit recognizes that exact canonical hook and does not create a project
duplicate:

```text
ctx integrate codex --hooks --user
ctx retrofit
```

The user-wide ctx hook exits successfully without adding context when the
working directory is outside a ctx project. Keep only one ctx hook definition
trusted for any particular repository.

The documented `/hooks` browser is a Codex CLI/TUI command. The Codex desktop
app does not currently expose it in its documented developer-command surface,
so do not use `/hooks` as a desktop setup step. Explicit ctx commands remain
fully usable there:

```text
ctx hydrate --task "Describe the work I am about to do"
ctx status --check
```

An agent can perform the same step when prompted to run `ctx hydrate` before it
reads or edits source. Until desktop exposes hook review, automatic prompt and
stop integration should be treated as a Codex CLI/TUI convenience, not as a
portable requirement. See the official [Codex hooks
documentation](https://learn.chatgpt.com/docs/hooks) and [developer-command
reference](https://learn.chatgpt.com/docs/developer-commands?surface=app).

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

### Git pre-commit freshness reminder

```text
ctx integrate git --hooks [--project PATH] [--block]
```

This create-only integration installs a project Git `pre-commit` hook. The
default hook is warning-only: it runs `ctx status --check` against the current
working tree, remains silent when everything is fresh, and otherwise tells the
developer to run `ctx reconcile`, review and stage the intended `.ctx` files,
then retry. Because the warning variant reads the working tree rather than
Git's staged blobs, it does not claim that a partially staged commit and its
staged lock are consistent.

`--block` opts into enforcement. The blocking hook refuses unstaged tracked
changes and nonignored untracked files before checking freshness, so the
working tree represents the staged index. A stale, unknown, or invalid result
then stops the commit. This conservative policy deliberately disallows partial
commits; stage or stash the other work before retrying.

The hook never invokes a model, runs reconciliation, modifies a manifest or
lock, changes the Git index, or creates a commit. It resolves `ctx` from the
hook process `PATH`. A different existing `pre-commit` hook and any configured
`core.hooksPath` are preserved rather than overwritten or merged. Default Git
hooks are shared by linked worktrees, so the generated hook derives the active
worktree root at runtime and exits silently when that root has no
`.ctx/context.yaml`. Choose warning or blocking mode at installation because a
different canonical variant is not silently substituted later.
`git commit --no-verify` bypasses the check. A missing root manifest that
remains tracked in the index or `HEAD` also warns or blocks; intentionally
decommissioning ctx requires removing the installed hook.

## Compatibility aliases

- `ctx retrofit prompt [PATH]` remains an alias for
  `ctx retrofit [PATH] --prompt`.
- `ctx retrofit review [PATH]` runs a mandatory dry-run even when the existing
  graph is fresh. It may propose only missing manifests and produces an exact
  saved plan for review and later `--apply`.
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
