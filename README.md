# ctx

`ctx` gives AI agents durable, project-specific context without putting the
whole repository into every prompt.

It stores meaning beside the source in version-controlled `.ctx/context.yaml`
files: important artifacts, invariants, architectural decisions, reusable
patterns, and links to related context.

> [!WARNING]
> **Experimental alpha.** The CLI and manifest schema may change before V1.
> Use ctx in version-controlled projects and review generated context and hooks.

## Install

Requires Python 3.11+, [`pipx`](https://pipx.pypa.io/), and
[Codex](https://developers.openai.com/codex/cli) installed and signed in.

```bash
pipx install git+https://github.com/crdunwel/ctx.git
ctx doctor
```

## Use it with Codex

From any project:

```bash
cd /path/to/project
ctx retrofit
```

That one command asks Codex to inspect a filtered read-only copy, creates a
small semantic `.ctx` graph, validates it, installs the project Codex hooks,
records freshness, and registers the checkout. It never gives the retrofit
agent write access to source or overwrites existing manifests.

Review `.ctx/` and `.codex/hooks.json` and commit them with the source. Open the
project in Codex, run `/hooks`, and review and trust the two project hooks. Then
use Codex normally. The prompt hook hydrates the current directory; the stop
hook checks whether source and durable context still agree.

## Try the sample project

Create a complete, ready-to-use example without invoking a model:

```bash
ctx demo /tmp/ctx-permit-board-demo
cd /tmp/ctx-permit-board-demo
codex
```

In Codex, run `/hooks` and review and trust the two project hooks. Then ask:

> How does an application become ready for review, and which rule has
> precedence?

Then move into the narrower policy context:

> Use ctx to follow the policy child scope. Why are fee and eligibility rules
> separate, and which tests prove the invariants?

Finally, try a real change:

> Add a waived-fee path for public agencies without making unpaid private
> applications ready.

The sample includes working source and tests, a root context, a nested policy
scope, Codex hooks, and a fresh lock. It demonstrates orientation, progressive
hydration as work moves through the tree, artifact routing, invariants, and
stop-time reconciliation. `ctx demo` never overwrites an existing path. Outside
an existing ctx project, bare `ctx demo` creates `./ctx-permit-board-demo`.

## Common commands

| Command | What it does |
|---|---|
| `ctx demo [PATH]` | Create the bundled, context-enabled sample |
| `ctx retrofit [PATH]` | Construct context and enable Codex for a project |
| `ctx hydrate` | Print task context for the current directory |
| `ctx show [REFERENCE]` | Inspect a project, node, item, or local scope |
| `ctx status` | Check whether source and context are synchronized |
| `ctx reconcile` | Review stale context with Codex and refresh it |
| `ctx validate --strict` | Validate the complete local context graph |
| `ctx register` | Register an existing context-enabled checkout |
| `ctx projects` | List registered projects |
| `ctx search "QUERY"` | Search registered projects, nodes, and items |
| `ctx resolve REFERENCE` | Resolve a name, alias, or exact `ctx://` URI |
| `ctx graph [REFERENCE]` | Show explicitly linked context |
| `ctx doctor` | Check Python, dependencies, registry, and Codex |
| `ctx help [COMMAND]` | Show broad or command-specific help |

Most commands use the current directory when no path is supplied.

## Common pathways

### Add ctx to a project

```bash
cd /path/to/project
ctx retrofit
git diff -- .ctx .codex
```

### Review retrofit before applying it

```bash
ctx retrofit --dry-run
ctx retrofit --show-plan PLAN_ID
ctx retrofit --apply PLAN_ID
```

The dry run invokes Codex but does not change the project. It prints the exact
commands containing the generated plan ID.

### Check or repair stale context

```bash
ctx status
ctx reconcile
```

### Hydrate a specific task or directory

```bash
ctx hydrate --from server/api --task "Change permit search behavior"
```

### Reuse context from another registered project

```bash
ctx search "progressive form"
ctx hydrate --task "Use the form pattern from Permit Atlas"
```

## Data and trust

Automated `ctx retrofit` and `ctx reconcile` fingerprint every eligible,
nonignored file, then give Codex a separate deterministic inspection corpus.
Complete source, instructions, contracts, and tests are prioritized across
project areas. Non-governing text files over 2 MiB and large structured files
receive bounded labeled previews; media, archives, databases, duplicates, and
protected top-level data may be represented by metadata or a small sample.
Structured JSON path relationships can reserve a few candidate source/output
media pairs. The normal copied-content target is 64 MiB under a 256 MiB absolute
whole-snapshot guard. Omitted content remains covered by freshness fingerprints.

The configured model provider may process selected files and previews and may
incur cost. Filtering is based on paths and filenames; it is not secret-content
detection. Exclude sensitive files before agent-assisted use. Generated
inspection catalogs and previews exist only in the temporary adapter workspace
and cannot become manifest artifacts.

Generated manifests are project data. They do not override the user,
repository instructions, security policy, or source code. Source remains
authoritative. Project hooks execute whichever `ctx` is first on Codex's
`PATH`, so inspect `.codex/hooks.json`, `command -v ctx`, and `ctx --version`
before trusting them.

Automatic guarded retrofit, reconciliation, and freshness currently require
macOS or Linux. Prompt generation and manual authoring remain portable.

## More

- [Complete CLI reference](docs/CLI.md)
- [Product and manifest contract](AGENTS.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

Licensed under the [Apache License 2.0](LICENSE).
