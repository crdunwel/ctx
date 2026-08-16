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

Requires Python 3.11+ and [`pipx`](https://pipx.pypa.io/). The guarded
agent-assisted `retrofit` and `reconcile` commands also require
[Codex](https://developers.openai.com/codex/cli) installed and signed in; the
rest of the CLI remains local and agent-neutral.

```bash
pipx install git+https://github.com/crdunwel/ctx.git
ctx doctor
```

## Get value in 60 seconds

To try ctx without invoking a model or changing an existing project:

```bash
ctx demo /tmp/ctx-permit-board-demo
cd /tmp/ctx-permit-board-demo
ctx hydrate --task "Explain how an application becomes ready for review"
```

The output is the exact bounded context packet an agent receives: active scope,
durable rules, routing to narrower scopes, and authoritative source paths.

For a real project, run:

```bash
cd /path/to/project
ctx retrofit
ctx hydrate --task "Orient me to this project and identify the best next scope"
```

`ctx retrofit` asks Codex to inspect a filtered read-only copy, creates a
small semantic `.ctx` graph, validates it, enables Codex hooks, records
freshness, and registers the checkout. It installs project hooks unless the
exact canonical user-wide hook already covers the project. It never gives the
retrofit agent write access to source or overwrites existing manifests.

Review `.ctx/` and any project `.codex/hooks.json`, then commit them with the
source. The explicit `ctx hydrate` command works immediately with any agent
that can run a CLI. `ctx` does not install a `/ctx` slash command or add an
item to Codex's command palette.

### Automatic hooks in the Codex CLI/TUI

Start the Codex CLI from the project, run `/hooks`, and review and trust the two
project hooks. Codex requires both the project `.codex` layer and each exact
non-managed command-hook definition to be trusted before project hooks run.
After that, use Codex normally: the prompt hook hydrates the current directory,
and the stop hook checks whether source and durable context still agree. See
the official [Codex hooks documentation](https://learn.chatgpt.com/docs/hooks).

Choose one ctx hook scope—user-wide or project—not both. Codex runs matching
hooks from multiple files concurrently, so trusting identical ctx hooks in
`~/.codex/hooks.json` and `<repo>/.codex/hooks.json` duplicates hydration and
stop checks. The default project hook is versioned and portable. For one-time
setup across all ctx projects instead, use:

```bash
ctx integrate codex --hooks --user
ctx retrofit
```

Bare retrofit detects the canonical user-wide hook and does not create a
duplicate project hook. The user-wide ctx hook exits successfully without
adding context outside a ctx project. Keep only one of the two ctx hook
definitions trusted for any given project.

`/hooks` is the Codex CLI/TUI hook browser. The Codex desktop app does not
currently expose `/hooks` in its documented developer-command surface. In the
desktop app, use the explicit workflow until hook review is available there:

```bash
ctx hydrate --task "Describe the work I am about to do"
ctx status --check
```

You can also tell the desktop agent: “Run `ctx hydrate` for this task before
reading source.” See the official developer-command
[reference](https://learn.chatgpt.com/docs/developer-commands?surface=app) for
the commands available on each Codex surface.

## Try the sample project

Create a complete example without invoking a model:

```bash
ctx demo /tmp/ctx-permit-board-demo
cd /tmp/ctx-permit-board-demo
ctx hydrate --task "How does an application become ready for review?"
```

To try automatic hydration, start the Codex CLI in this directory, run `/hooks`,
and review and trust the two project hooks. Then ask:

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
| `ctx doctor [PATH]` | Check Python, registry, Codex, and project/user hooks |
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

To look for missing semantic scopes in a project whose existing graph is
already fresh, run `ctx retrofit review`. Review mode is always a dry run;
existing manifests remain protected and only missing node manifests may appear
in the saved proposal.

An output beginning with `RETROFIT UNCHANGED` is a successful idempotent result:
the current graph already passed strict validation and matched its freshness
lock, so bare retrofit did not spend another model call or rewrite reviewed
context. To deliberately audit it again, use:

```bash
ctx retrofit review
ctx retrofit --show-plan PLAN_ID
ctx retrofit --apply PLAN_ID
```

Review prints a saved plan ID and never changes the project. Applying is a
separate step and is refused if the proposal contains unresolved areas or
review-required conflicts. During the model review, ctx prints concise stages
and a ten-second elapsed heartbeat; `Ctrl-C` stops safely before publication.

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
Retrofit prioritizes complete source, instructions, contracts, and tests across
bounded hierarchical project areas. Reconciliation limits model-visible source
to affected-node ownership and declared evidence while retaining the complete
fingerprint for race detection. Non-governing text files over 2 MiB and large
structured files receive bounded labeled previews; media, archives, databases,
duplicates, and protected top-level data may be represented by metadata or a
small sample.
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
