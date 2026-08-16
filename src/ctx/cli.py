from __future__ import annotations

import argparse
import importlib.metadata
import json
import shlex
import sys
import unicodedata
from functools import partial
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .codex_cli import find_codex_executable
from .codex_hooks import (
    acknowledge_run,
    codex_prompt_output,
    codex_stop_output,
    complete_run,
    inspect_run,
    read_hook_input,
)
from .diagnostics import CtxError, Diagnostic, NotFoundError
from .demo import create_demo
from .freshness import project_status
from .graph import context_graph
from .hydration import DEFAULT_BUDGET, hydrate
from .integration import diagnose_codex_hooks, install_codex_hooks
from .lifecycle import RetrofitLifecycleResult, complete_retrofit
from .registry import (
    load_registry,
    register_project,
    resolve_project,
    unregister_project,
)
from .reconciliation import generate_reconcile_prompt, reconcile_project
from .retrofit import generate_retrofit_prompt
from .retrofit_agent import (
    apply_retrofit_plan,
    render_retrofit_plan,
    run_agent_retrofit,
)
from .runs import begin_run, load_run
from .services import (
    ShowResult,
    init_node,
    init_project,
    show,
    validation_to_dict,
)
from .validation import ValidationResult, validate_project
from .universe import resolve_reference, search_context


class CtxArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CtxError("cli.invalid", message, exit_code=1)


class CtxHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """Readable command help with explicit positionals and named options."""

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            return action.metavar or action.dest.upper()
        return super()._format_action_invocation(action)


def _command_parser(commands: Any, name: str, **kwargs: Any) -> argparse.ArgumentParser:
    return commands.add_parser(name, formatter_class=CtxHelpFormatter, **kwargs)


def build_parser(*, prog: str = "ctx") -> argparse.ArgumentParser:
    parser = CtxArgumentParser(
        prog=prog,
        description=(
            "Build, retrieve, and maintain local-first project context "
            "(experimental alpha)."
        ),
        epilog=(
            "Run `ctx help COMMAND` or `ctx COMMAND --help` for every positional "
            "argument and named option. Most commands default to the current directory."
        ),
        formatter_class=CtxHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    help_parser = _command_parser(
        commands,
        "help",
        help="show broad or command-specific help",
        description="Show broad help or every positional argument and named option for one command.",
    )
    help_parser.add_argument("topic", nargs="?", help="command whose help should be shown")

    demo = _command_parser(
        commands,
        "demo",
        help="create a ready-to-use sample project",
        description=(
            "Create a complete Permit Board sample with source, tests, semantic "
            "context, a fresh lock, and project Codex hooks. No model is invoked."
        ),
    )
    demo.add_argument(
        "path",
        nargs="?",
        default="ctx-permit-board-demo",
        help="new directory outside any ctx project; it must not already exist",
    )

    init = _command_parser(
        commands,
        "init",
        help="create a project root manifest",
        description="Create a missing root .ctx/context.yaml without overwriting an existing manifest.",
    )
    init.add_argument("path", nargs="?", default=".", help="project directory")
    init.add_argument("--id", dest="project_id", help="stable lowercase project ID")
    init.add_argument("--name", help="human project name")
    init.add_argument("--alias", action="append", default=[], help="repeatable lookup alias")

    node = _command_parser(
        commands,
        "node",
        help="create a semantic child node",
        description=(
            "Create a missing nested .ctx/context.yaml. Compatibility form: "
            "ctx node init [PATH] ..."
        ),
    )
    node.add_argument("path", nargs="?", default=".", help="semantic node directory")
    node.add_argument("--id", dest="node_id", required=True, help="stable lowercase node ID")
    node.add_argument("--name", required=True, help="human node name")
    node.add_argument("--summary", help="concise durable purpose")

    show_parser = _command_parser(
        commands,
        "show",
        help="show inherited or resolved context",
        description="Show context for the current directory, another path, or a registered reference.",
    )
    show_parser.add_argument("reference", nargs="?", default=".", help="path, project, alias, or ctx:// URI")
    show_parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    validate = _command_parser(
        commands,
        "validate",
        help="validate a local context project",
        description="Validate the complete containing project without modifying it.",
    )
    validate.add_argument("path", nargs="?", default=".", help="path inside the project")
    validate.add_argument("--strict", action="store_true", help="promote actionable warnings to failures")
    validate.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    register = _command_parser(
        commands,
        "register",
        help="register a validated checkout",
        description="Strictly validate and add the containing project to the disposable local registry.",
    )
    register.add_argument("path", nargs="?", default=".", help="path inside the project")

    unregister = _command_parser(
        commands,
        "unregister",
        help="remove a project from the registry",
        description="Remove only disposable discovery state; repository files are untouched.",
    )
    unregister.add_argument("project", help="registered project ID, name, or alias")

    projects = _command_parser(
        commands,
        "projects",
        help="list registered projects",
        description="List the disposable local registry in deterministic order.",
    )
    projects.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    resolve = _command_parser(
        commands,
        "resolve",
        help="resolve an exact context reference",
        description="Resolve a project, node, item, alias, or ctx:// URI without broad guessing.",
    )
    resolve.add_argument("reference", help="project, alias, node/item identity, title, or ctx:// URI")
    resolve.add_argument("--project", help="limit symbolic resolution to one project")
    resolve.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    search = _command_parser(
        commands,
        "search",
        help="search registered context",
        description="Lexically search the small manifests of registered projects.",
    )
    search.add_argument("query", help="words to search for")
    search.add_argument("--project", help="limit search to a project ID, name, or alias")
    search.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    graph = _command_parser(
        commands,
        "graph",
        help="show an explicitly linked context graph",
        description="Traverse explicit links with a visited set and a small deterministic depth bound.",
    )
    graph.add_argument("reference", nargs="?", help="path, project, alias, or ctx:// URI")
    graph.add_argument("--from", dest="from_path", default=".", help="local starting path when REFERENCE is omitted")
    graph.add_argument("--depth", type=int, default=1, help="maximum explicit-link depth")
    graph.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    hydrate_parser = _command_parser(
        commands,
        "hydrate",
        help="emit task-specific context",
        description=(
            "Hydrate the nearest semantic scope fully, list its immediate child scopes "
            "as dormant routing references, compact inherited constraints, and include "
            "only additional context explicitly named by URI, project, or --include. "
            "Authored links remain references until requested."
        ),
    )
    hydrate_parser.add_argument("reference", nargs="?", help="optional exact local or registered context reference")
    hydrate_parser.add_argument("--from", dest="from_path", default=".", help="path where work will occur")
    hydrate_parser.add_argument("--task", help="task text used for exact ctx:// and explicit project-name detection")
    hydrate_parser.add_argument("--include", action="append", default=[], help="repeatable exact reference to include")
    hydrate_parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="approximate output token budget")
    hydrate_parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    status = _command_parser(
        commands,
        "status",
        help="report deterministic context freshness",
        description="Compare current source and manifest fingerprints with the root .ctx/lock.json.",
    )
    status.add_argument("target", nargs="?", default=".", help="path or registered project")
    status.add_argument("--check", action="store_true", help="exit nonzero unless all nodes are valid and fresh")
    status.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    begin = _command_parser(
        commands,
        "begin",
        help="capture an immutable task baseline",
        description=(
            "Capture the pre-edit semantic-node and Git baseline for one task. "
            "Codex prompt hooks normally invoke this automatically."
        ),
    )
    begin.add_argument("--from", dest="from_path", default=".", help="path where work will occur")
    begin.add_argument("--task", required=True, help="task whose edits will be reconciled")
    begin.add_argument("--session", help="optional host-agent session ID")
    begin.add_argument("--turn", help="optional host-agent turn ID")
    begin.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    doctor = _command_parser(
        commands,
        "doctor",
        help="check the local ctx environment",
        description=(
            "Inspect Python, PyYAML, registry, guarded Codex adapter availability, "
            "and project/user hook configuration without changing anything. Codex "
            "discovery checks CTX_CODEX, PATH, then the standard macOS ChatGPT app "
            "bundle; hook trust itself is not inspectable."
        ),
    )
    doctor.add_argument(
        "path",
        nargs="?",
        default=".",
        help="path from which to diagnose project and user Codex hooks",
    )
    doctor.add_argument("--json", action="store_true", help="emit one machine-readable JSON document")

    reconcile = _command_parser(
        commands,
        "reconcile",
        help="review stale context and refresh freshness",
        description=(
            "Use a guarded read-only agent snapshot to update only affected existing "
            "manifests or acknowledge implementation-only changes, then strictly validate "
            "and refresh the lock. Eligible source is fully fingerprinted while a bounded "
            "selection may be processed by the configured model provider; path filtering "
            "is not secret-content detection."
        ),
        epilog=(
            "Use --prompt for a model-free handoff. Exclude sensitive files before agent "
            "modes and inspect proposed manifest text before committing it."
        ),
    )
    reconcile.add_argument("target", nargs="?", default=".", help="path or registered project")
    reconcile_modes = reconcile.add_mutually_exclusive_group()
    reconcile_modes.add_argument(
        "--prompt",
        action="store_true",
        help="print the standalone prompt without invoking an agent or transmitting source",
    )
    reconcile_modes.add_argument(
        "--dry-run",
        action="store_true",
        help="invoke the agent and validate a transient proposal without applying it; exact YAML is not retained",
    )
    reconcile.add_argument("--agent", default="codex", help="configured local agent adapter")
    reconcile_modes.add_argument(
        "--acknowledge",
        metavar="REASON",
        help="explicitly accept all current affected nodes without manifest edits",
    )
    reconcile_modes.add_argument(
        "--inspect",
        nargs="?",
        const="",
        metavar="REFERENCE",
        help="inspect changes since an immutable --run baseline; optionally limit to one local node",
    )
    reconcile_modes.add_argument(
        "--acknowledge-node",
        metavar="REFERENCE",
        help="acknowledge one run-affected node as implementation-only",
    )
    reconcile_modes.add_argument(
        "--complete-run",
        action="store_true",
        help="strictly validate and selectively seal a reviewed run",
    )
    reconcile.add_argument("--run", dest="run_id", help="immutable run ID for inspect/acknowledge/complete")
    reconcile.add_argument("--reason", help="reason for --acknowledge-node")
    reconcile.add_argument("--json", action="store_true", help="emit one machine-readable JSON document for --inspect")

    retrofit = _command_parser(
        commands,
        "retrofit",
        help="construct missing context with a local agent",
        description=(
            "Inspect a project with the local Codex CLI and construct only "
            "missing, strict-valid .ctx/context.yaml files, then install the "
            "canonical Codex hooks (or reuse an exact user-wide installation), "
            "initialize freshness, and register it. Eligible "
            "source is fully fingerprinted while a deterministic bounded selection "
            "may be processed by the configured model provider."
        ),
        epilog=(
            "Use `ctx retrofit --prompt [PATH]` (or compatibility form "
            "`ctx retrofit prompt [PATH]`) to print the standalone prompt without starting an agent. "
            "Use `ctx retrofit review [PATH]` to inspect a fresh existing graph and save a "
            "reviewable proposal for missing semantic nodes. "
            "A successful --dry-run prints --show-plan and --apply commands for that exact proposal. "
            "Path filtering is not secret-content detection: exclude sensitive files and inspect "
            "the plan and .ctx diff before committing. Large media and data may be sampled, "
            "previewed, or cataloged without weakening freshness. Use --no-hooks only when Codex "
            "integration is intentionally unwanted."
        ),
    )
    retrofit.add_argument(
        "path",
        nargs="?",
        default=argparse.SUPPRESS,
        help="project directory; omit to use the current directory",
    )
    retrofit_modes = retrofit.add_mutually_exclusive_group()
    retrofit_modes.add_argument(
        "--prompt",
        dest="prompt_only",
        action="store_true",
        help="print the standalone prompt without invoking an agent or transmitting source",
    )
    retrofit_modes.add_argument(
        "--dry-run",
        action="store_true",
        help="invoke the agent and save an exact validated proposal without applying project changes",
    )
    retrofit_modes.add_argument(
        "--apply",
        metavar="PLAN_ID",
        default=argparse.SUPPRESS,
        help="apply the exact validated proposal saved by --dry-run without starting an agent",
    )
    retrofit_modes.add_argument(
        "--show-plan",
        metavar="PLAN_ID",
        default=argparse.SUPPRESS,
        help="print a saved dry-run proposal as terminal-safe JSON without starting an agent",
    )
    retrofit.add_argument("--agent", default="codex", help="configured local agent adapter")
    retrofit.add_argument(
        "--review",
        action="store_true",
        help=(
            "review semantic coverage even when existing context is fresh; "
            "requires --dry-run and may propose only missing manifests"
        ),
    )
    retrofit.add_argument(
        "--no-hooks",
        action="store_true",
        help="do not enable Codex hydration/reconciliation hooks",
    )

    hook = _command_parser(
        commands,
        "hook",
        help="run an agent lifecycle adapter",
        description="Read one documented host hook JSON object from stdin and emit one hook JSON result.",
    )
    hook_commands = hook.add_subparsers(dest="hook_command", required=True, metavar="ADAPTER")
    _command_parser(
        hook_commands,
        "codex-prompt",
        help="hydrate and begin/reuse a Codex turn run",
        description="Handle the Codex UserPromptSubmit event from JSON on stdin.",
    )
    _command_parser(
        hook_commands,
        "codex-stop",
        help="check and steer Codex turn reconciliation",
        description="Handle the Codex Stop event from JSON on stdin with at most one continuation.",
    )

    integrate = _command_parser(
        commands,
        "integrate",
        help="install an optional agent integration",
        description="Install a reviewed, create-only integration for a supported host agent.",
    )
    integrate_commands = integrate.add_subparsers(
        dest="integration_command", required=True, metavar="AGENT"
    )
    integrate_codex = _command_parser(
        integrate_commands,
        "codex",
        help="install Codex hydration and Stop hooks",
        description=(
            "Create the canonical UserPromptSubmit and Stop hooks. Codex must review "
            "and trust project-local hook definitions before they run. The generated "
            "commands resolve ctx from the Codex hook process PATH."
        ),
    )
    integrate_codex.add_argument("--hooks", action="store_true", required=True, help="install the ctx Codex hooks")
    integrate_scope = integrate_codex.add_mutually_exclusive_group()
    integrate_scope.add_argument("--user", action="store_true", help="install at ~/.codex/hooks.json for every workspace")
    integrate_scope.add_argument("--project", metavar="PATH", help="ctx project path; defaults to the current project")
    return parser


def _write_json(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def _error_json(error: CtxError) -> dict[str, Any]:
    return {
        "schema": "ctx-error/v1",
        "error": {"code": error.code, "message": error.message},
    }


def _safe_display(value: object) -> str:
    """Render untrusted manifest text without terminal control sequences."""
    text = str(value)
    rendered: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in {"\n", "\r", "\t"}:
            rendered.append(" ")
        elif (
            codepoint < 32
            or codepoint == 127
            or 0x80 <= codepoint <= 0x9F
            or unicodedata.category(character) == "Cf"
        ):
            rendered.append(f"\\u{codepoint:04x}")
        else:
            rendered.append(character)
    return " ".join("".join(rendered).split())


def _retrofit_hooks_summary(result: RetrofitLifecycleResult) -> str:
    hooks = result.hooks
    if hooks is None:
        return "hooks skipped"
    summary = f"hooks {hooks.action} at {_safe_display(hooks.path)}"
    if hooks.scope == "user":
        summary += (
            " (user-wide; no duplicate project hook created; "
            "Codex CLI/TUI trust is managed in /hooks)"
        )
    elif hooks.action == "created":
        summary += " (Codex CLI/TUI: run /hooks, then review and trust it)"
    return summary


def _retrofit_progress(message: str) -> None:
    print(f"ctx retrofit: {_safe_display(message)}", file=sys.stderr, flush=True)


def _print_retrofit_next_steps(root: Path) -> None:
    quoted_root = shlex.quote(str(root))
    task = shlex.quote("Map this project and route me to its main semantic scopes")
    print("Try the context now (read-only):")
    print(f"  ctx status {quoted_root} --check")
    print(f"  ctx doctor {quoted_root}")
    print(f"  ctx hydrate --from {quoted_root} --task {task}")
    print("Re-audit a fresh graph for missing scopes (project files stay unchanged):")
    print(f"  ctx retrofit review {quoted_root}")


def _render_diagnostic(diagnostic: Diagnostic) -> str:
    location = str(diagnostic.manifest) if diagnostic.manifest is not None else "<context>"
    if diagnostic.field:
        location += f":{diagnostic.field}"
    return _safe_display(
        f"{diagnostic.severity.upper()} {diagnostic.code} "
        f"{location}: {diagnostic.message}"
    )


def _render_show(result: ShowResult) -> None:
    ancestry = result.ancestry
    print(
        f"Project: {_safe_display(ancestry.project.name)} "
        f"({_safe_display(ancestry.project.id)})"
    )
    print(f"Root: {ancestry.project_root}")
    print(f"Path: {ancestry.resolved_path}")
    print(f"Current: {ancestry.current.uri}")
    if result.selected_uri is not None:
        print(f"Selected: {result.selected_uri}")
    print(
        f"Validation: valid ({sum(value.severity == 'warning' for value in result.diagnostics)} warning(s))"
    )
    for loaded in ancestry.nodes:
        manifest = loaded.manifest
        print()
        print(f"{loaded.uri} — {_safe_display(manifest.node.name)}")
        print(f"  Manifest: {loaded.document.path}")
        if manifest.node.summary:
            print(f"  Purpose: {_safe_display(manifest.node.summary)}")
        if manifest.artifacts:
            print("  Artifacts:")
            for artifact in manifest.artifacts:
                absolute = (
                    loaded.document.node_dir / artifact.path
                ).resolve(strict=False)
                print(f"    {absolute} — {_safe_display(artifact.role)}")
        if manifest.items:
            print("  Durable items:")
            for item in manifest.items:
                print(
                    f"    [{item.kind}] {_safe_display(item.title)} "
                    f"({item.id}): {_safe_display(item.summary)}"
                )
                if item.reason:
                    print(f"      Reason: {_safe_display(item.reason)}")
                if item.artifacts:
                    print(
                        "      Evidence artifacts: "
                        + ", ".join(_safe_display(value) for value in item.artifacts)
                    )
                if item.adoption:
                    print(f"      Adoption: {item.adoption.mode}")
                    for label in ("requires", "adapt", "verify"):
                        entries = getattr(item.adoption, label)
                        if entries:
                            rendered = ", ".join(_safe_display(value) for value in entries)
                            print(f"      {label.title()}: {rendered}")
                if item.supersedes:
                    print(
                        "      Supersedes: "
                        + ", ".join(_safe_display(value) for value in item.supersedes)
                    )
        if manifest.links:
            print("  Links:")
            for link in manifest.links:
                optional = " (optional)" if link.optional else ""
                print(
                    f"    {_safe_display(link.relation)} -> "
                    f"{_safe_display(link.target)}{optional}"
                )
        if manifest.tracking.include or manifest.tracking.exclude:
            print("  Tracking:")
            if manifest.tracking.include:
                print(
                    "    Include: "
                    + ", ".join(_safe_display(value) for value in manifest.tracking.include)
                )
            if manifest.tracking.exclude:
                print(
                    "    Exclude: "
                    + ", ".join(_safe_display(value) for value in manifest.tracking.exclude)
                )
    for diagnostic in result.diagnostics:
        if diagnostic.severity == "warning":
            print(_render_diagnostic(diagnostic), file=sys.stderr)


def _target_path(value: str) -> Path:
    candidate = Path(value)
    if candidate.exists():
        return candidate
    return resolve_project(value).root


def _render_status(result: Any) -> None:
    label = "FRESH" if result.fresh else "ATTENTION"
    print(f"{label} {result.project_id}: {len(result.nodes)} node(s)")
    if result.lock_error:
        print(f"  lock: {_safe_display(result.lock_error)}")
    for node in result.nodes:
        print(f"  {node.state:15} {node.uri} ({node.files} file(s))")


def _render_graph(result: Any) -> None:
    print(f"Graph: {result.root} (depth {result.depth})")
    for node in result.nodes:
        title = node.item.title if node.item is not None else node.node.manifest.node.name
        print(f"  {node.uri} — {_safe_display(title)}")
    for edge in result.edges:
        state = "" if edge.resolved else " [unresolved]"
        print(f"  {edge.source} --{edge.relation}--> {edge.target}{state}")
    for warning in result.warnings:
        print(f"WARNING graph: {_safe_display(warning)}", file=sys.stderr)


def _render_validation(result: ValidationResult) -> None:
    label = "VALID" if result.valid else "INVALID"
    print(
        f"{label} {result.project.id}: {len(result.nodes)} node(s), "
        f"{len(result.errors)} error(s), {len(result.warnings)} warning(s)"
    )
    for diagnostic in result.diagnostics:
        print(_render_diagnostic(diagnostic), file=sys.stderr)


def _render_run_inspection(payload: dict[str, Any]) -> None:
    print(
        f"RUN {payload['run_id']} — {payload['status']}; "
        f"{len(payload['changes'])} affected node(s)"
    )
    limitation = payload["baseline"].get("limitation")
    if limitation:
        print(f"  Baseline: {_safe_display(limitation)}")
    path_limitation = payload.get("path_attribution_limitation")
    if path_limitation and path_limitation != limitation:
        print(f"  Paths: {_safe_display(path_limitation)}")
    for changed_path in payload.get("changed_paths", []):
        origin = "pre-existing" if changed_path["preexisting_at_start"] else "this run"
        print(f"  Path ({origin}): {_safe_display(changed_path['path'])}")
    for change in payload["changes"]:
        state: list[str] = []
        if change["source_changed"]:
            state.append("source")
        if change["context_changed"]:
            state.append("context")
        if change["added"]:
            state.append("added")
        if change["removed"]:
            state.append("removed")
        coverage = "covered" if change["covered"] else "REVIEW REQUIRED"
        print(f"  {coverage:15} {change['uri']} ({', '.join(state)})")
        if change["manifest"]:
            print(f"    Manifest: {change['manifest']}")
        if change["acknowledgement"]:
            print(f"    Acknowledged: {_safe_display(change['acknowledgement'])}")
            if not change.get("acknowledgement_current", False):
                print("    Acknowledgement is stale; review the latest node state again.")
    for command in payload.get("inspection_commands", []):
        print(f"  Inspect: {_safe_display(command)}")


def _execute(args: argparse.Namespace) -> int:
    if args.command == "demo":
        result = create_demo(Path(args.path))
        quoted_root = shlex.quote(str(result.root))
        print(f"DEMO READY {result.root}")
        print(f"  Context: {len(result.manifests)} semantic node(s); fresh lock at {result.lock}")
        print(f"  Codex hooks: {result.hooks}")
        print("  Codex CLI/TUI: run /hooks and review and trust the two project hooks.")
        print(
            "  Codex desktop: /hooks is not available; run "
            'ctx hydrate --from . --task "Map this project" immediately.'
        )
        print("Next:")
        print(f"  cd {quoted_root}")
        print("  codex")
        print("Ask Codex:")
        print('  "How does an application become ready for review, and which rule has precedence?"')
        print('  "Use ctx to follow the policy child scope. Why are fee and eligibility rules separate, and which tests prove the invariants?"')
        print('  "Add a waived-fee path for public agencies without making unpaid private applications ready."')
        return 0
    if args.command == "init":
        result = init_project(
            Path(args.path),
            project_id=args.project_id,
            name=args.name,
            aliases=args.alias,
        )
        print(f"{result.action} {result.manifest_path}")
        return 0
    if args.command == "node":
        result = init_node(
            Path(args.path),
            node_id=args.node_id,
            name=args.name,
            summary=args.summary,
        )
        print(f"{result.action} {result.manifest_path}")
        return 0
    if args.command == "show":
        result = show(args.reference)
        if args.json:
            _write_json(result.to_dict())
        else:
            _render_show(result)
        return 0
    if args.command == "validate":
        result = validate_project(Path(args.path), strict=args.strict)
        if args.json:
            _write_json(validation_to_dict(result))
        else:
            _render_validation(result)
        if result.valid:
            return 0
        return 3 if result.unsafe else 1
    if args.command == "register":
        result = register_project(Path(args.path))
        print(f"{result.action} {result.entry.project_id} at {result.entry.root}")
        return 0
    if args.command == "unregister":
        entry = unregister_project(args.project)
        print(f"unregistered {entry.project_id} from {entry.root}")
        return 0
    if args.command == "projects":
        registry = load_registry()
        payload = {
            "schema": "ctx-projects/v1",
            "registry": str(registry.path),
            "projects": [
                {
                    "id": entry.project_id,
                    **entry.to_dict(),
                    "available": entry.root.is_dir(),
                }
                for entry in registry.projects
            ],
        }
        if args.json:
            _write_json(payload)
        elif not registry.projects:
            print("No registered projects.")
        else:
            for entry in registry.projects:
                state = "available" if entry.root.is_dir() else "stale"
                print(f"{entry.project_id:24} {state:9} {entry.name} — {entry.root}")
        return 0
    if args.command == "resolve":
        result = resolve_reference(args.reference, project=args.project)
        if args.json:
            _write_json(result.to_dict())
        else:
            print(f"{result.uri} — {result.project.entry.name}")
            print(f"  Manifest: {result.node.document.path}")
            print(f"  Directory: {result.node.document.node_dir}")
            if result.item is not None:
                print(f"  [{result.item.kind}] {_safe_display(result.item.title)}")
                print(f"  {_safe_display(result.item.summary)}")
        return 0
    if args.command == "search":
        hits = search_context(args.query, project=args.project)
        if args.json:
            _write_json(
                {
                    "schema": "ctx-search/v1",
                    "query": args.query,
                    "project": args.project,
                    "results": [hit.to_dict() for hit in hits],
                }
            )
        elif not hits:
            print("No context matches.")
        else:
            for hit in hits:
                print(f"{hit.uri} — [{hit.kind}] {_safe_display(hit.title)}")
                if hit.summary:
                    print(f"  {_safe_display(hit.summary)}")
                matched = ", ".join(hit.matched_tokens) or "none"
                print(
                    f"  match={hit.match_kind} field={hit.matched_field} "
                    f"tokens={matched}; trust={hit.trust}; reuse={hit.reuse_policy}"
                )
        return 0
    if args.command == "graph":
        result = context_graph(
            args.reference,
            from_path=Path(args.from_path),
            depth=args.depth,
        )
        if args.json:
            _write_json(result.to_dict())
        else:
            _render_graph(result)
        return 0
    if args.command == "hydrate":
        result = hydrate(
            from_path=Path(args.from_path),
            reference=args.reference,
            task=args.task,
            includes=args.include,
            budget=args.budget,
        )
        if args.json:
            _write_json(result.to_dict())
        else:
            sys.stdout.write(result.to_markdown())
        return 0
    if args.command == "status":
        result = project_status(_target_path(args.target))
        if args.json:
            _write_json(result.to_dict())
        else:
            _render_status(result)
        return 0 if (not args.check or result.fresh) else 1
    if args.command == "begin":
        result = begin_run(
            Path(args.from_path),
            task=args.task,
            session_id=args.session,
            turn_id=args.turn,
        )
        payload = {
            "schema": "ctx-begin/v1",
            "run_id": result.run_id,
            "project": {"id": result.project_id, "root": str(result.project_root)},
            "starting_scope": result.starting_uri,
            "session_id": result.session_id,
            "turn_ids": list(result.turn_ids),
            "baseline": {
                "nodes": len(result.baseline_nodes),
                "git_head": result.baseline_git_head,
                "preexisting_dirty_files": len(result.baseline_dirty_files),
                "limitation": result.baseline_limitation,
            },
            "marker": f"CTX_RECONCILE_RUN={result.run_id}",
        }
        if args.json:
            _write_json(payload)
        else:
            print(f"began {result.run_id} at {result.starting_uri}")
            print(payload["marker"])
        return 0
    if args.command == "doctor":
        try:
            yaml_version = importlib.metadata.version("PyYAML")
        except importlib.metadata.PackageNotFoundError:
            yaml_version = None
        resolved_codex = find_codex_executable()
        codex = str(resolved_codex.path) if resolved_codex is not None else None
        codex_source = resolved_codex.source if resolved_codex is not None else None
        try:
            registry = load_registry()
            registry_state = "valid"
            project_count = len(registry.projects)
            registry_location = registry.path
        except CtxError as exc:
            registry_state = f"invalid ({exc.code})"
            project_count = 0
            from .registry import registry_path

            registry_location = registry_path()
        try:
            hook_diagnosis = diagnose_codex_hooks(Path(args.path))
        except NotFoundError:
            hook_diagnosis = None
        payload = {
            "schema": "ctx-doctor/v1",
            "ok": yaml_version is not None,
            "ctx_version": __version__,
            "python": sys.version.split()[0],
            "pyyaml": yaml_version,
            "codex": codex,
            "codex_source": codex_source,
            "registry": {
                "path": str(registry_location),
                "state": registry_state,
                "projects": project_count,
            },
            "codex_hooks": (
                None if hook_diagnosis is None else hook_diagnosis.to_dict()
            ),
        }
        if args.json:
            _write_json(payload)
        else:
            print(f"ctx {__version__}")
            print(f"Python: {payload['python']}")
            print(f"PyYAML: {yaml_version or 'missing'}")
            adapter = codex or "not found (prompt modes remain available)"
            if codex_source is not None:
                adapter += f" ({codex_source})"
            print(f"Codex adapter: {adapter}")
            print(f"Registry: {registry_location} — {registry_state}; {project_count} project(s)")
            if hook_diagnosis is None:
                print(f"Ctx project: none found from {_safe_display(args.path)}")
            else:
                print(f"Ctx project: {hook_diagnosis.project_root}")
                print(
                    "Codex project hooks: "
                    f"{hook_diagnosis.project.status} at {hook_diagnosis.project.path}"
                )
                print(
                    "Codex user hooks: "
                    f"{hook_diagnosis.user.status} at {hook_diagnosis.user.path}"
                )
                if hook_diagnosis.possible_duplicate_execution:
                    print(
                        "WARNING: canonical ctx hooks exist at both project and user "
                        "scope; Codex may run both. Keep one scope."
                    )
                print("Hook trust: not inspectable by ctx")
                for recommendation in hook_diagnosis.recommendations:
                    print(f"  Next: {_safe_display(recommendation)}")
        return 0 if payload["ok"] else 4
    if args.command == "reconcile":
        if args.inspect is not None or args.acknowledge_node is not None or args.complete_run:
            if args.dry_run or args.target != "." or args.agent != "codex":
                raise CtxError(
                    "cli.invalid",
                    "run-scoped reconcile operations do not accept TARGET, --dry-run, or --agent",
                    exit_code=1,
                )
            if args.run_id is None:
                raise CtxError(
                    "run.required",
                    "run-scoped reconciliation requires --run ID",
                    exit_code=1,
                )
            run = load_run(args.run_id)
            if args.inspect is not None:
                payload = inspect_run(run, args.inspect or None)
                if args.json:
                    _write_json(payload)
                else:
                    _render_run_inspection(payload)
                return 0
            if args.acknowledge_node is not None:
                if args.reason is None:
                    raise CtxError(
                        "run.reason-required",
                        "reconcile acknowledge requires --reason REASON",
                        exit_code=1,
                    )
                updated = acknowledge_run(run, args.acknowledge_node, args.reason)
                print(f"acknowledged {args.acknowledge_node} for run {updated.run_id}")
                return 0
            completed = complete_run(run)
            action = "unchanged" if completed.lock is None else completed.lock.action
            print(
                f"completed {completed.run.run_id}: "
                f"{len(completed.changes)} affected node(s); lock {action}"
            )
            return 0
        if args.run_id is not None or args.reason is not None or args.json:
            raise CtxError(
                "cli.invalid",
                "--run, --reason, and reconcile --json require inspect, acknowledge, or complete",
                exit_code=1,
            )
        target = _target_path(args.target)
        if args.prompt:
            sys.stdout.write(generate_reconcile_prompt(target))
            return 0
        if args.agent != "codex" and args.acknowledge is None:
            raise CtxError(
                "reconcile.agent-unsupported",
                f"no guarded adapter is installed for agent {args.agent!r}; use --prompt",
                exit_code=1,
            )
        result = reconcile_project(
            target,
            dry_run=args.dry_run,
            acknowledge_reason=args.acknowledge,
        )
        if not result.validation.valid:
            _render_validation(result.validation)
            return 3 if result.validation.unsafe else 1
        if result.dry_run:
            print(
                f"RECONCILE DRY RUN {result.root}: "
                f"{len(result.changed_manifests)} manifest(s) proposed; "
                f"{len(result.acknowledgements)} node(s) acknowledged; no files changed"
            )
        elif result.lock is None:
            print(f"RECONCILE UNCHANGED {result.root}: already fresh")
        else:
            print(
                f"RECONCILE COMPLETE {result.root}: "
                f"{len(result.changed_manifests)} manifest(s) updated; "
                f"{len(result.acknowledgements)} node(s) acknowledged; lock {result.lock.action}"
            )
        if result.summary.strip():
            print(f"Agent summary: {_safe_display(result.summary)}")
        return 0
    if args.command == "retrofit":
        retrofit_path = getattr(args, "path", None)
        retrofit_plan = getattr(args, "apply", None)
        shown_plan = getattr(args, "show_plan", None)
        target = Path(retrofit_path or ".")
        if args.review and not args.dry_run:
            raise CtxError(
                "cli.invalid",
                "--review requires --dry-run so semantic coverage proposals are reviewed before application",
                exit_code=1,
            )
        finalize_retrofit = partial(
            complete_retrofit,
            enable_codex_hooks=not args.no_hooks,
        )
        if args.prompt_only:
            sys.stdout.write(generate_retrofit_prompt(target))
            return 0
        if shown_plan is not None:
            if retrofit_path is not None:
                raise CtxError(
                    "cli.invalid",
                    "PATH is not accepted with --show-plan; the saved plan identifies its project",
                    exit_code=1,
                )
            sys.stdout.write(render_retrofit_plan(shown_plan))
            return 0
        if retrofit_plan is not None:
            result = apply_retrofit_plan(
                retrofit_plan,
                path=None if retrofit_path is None else target,
                finalize=finalize_retrofit,
            )
            _render_validation(result.validation)
            if not result.validation.valid:
                return 3 if result.validation.unsafe else 1
            if not isinstance(result.finalization, RetrofitLifecycleResult):
                raise CtxError(
                    "retrofit.lifecycle-incomplete",
                    "retrofit manifests validated but lifecycle finalization did not complete",
                    exit_code=4,
                )
            registration = result.finalization.registration
            lock = result.finalization.lock
            hooks_summary = _retrofit_hooks_summary(result.finalization)
            print(
                f"RETROFIT COMPLETE {result.root}: "
                f"{len(result.created_manifests)} manifest(s) created from saved plan "
                f"{result.plan_id}; registry {registration.action}; lock {lock.action}; "
                f"{hooks_summary}"
            )
            if result.agent_summary.strip():
                print(f"Agent summary: {_safe_display(result.agent_summary)}")
            _print_retrofit_next_steps(result.root)
            return 0
        try:
            existing_status = project_status(target)
        except NotFoundError:
            existing_status = None
        if existing_status is not None and existing_status.fresh and not args.review:
            if args.dry_run:
                print(
                    f"RETROFIT DRY RUN {existing_status.root}: already strict-valid "
                    "and fresh; no agent needed and no files changed"
                )
                _print_retrofit_next_steps(existing_status.root)
                return 0
            finalization = finalize_retrofit(existing_status.root)
            hooks_summary = _retrofit_hooks_summary(finalization)
            print(
                f"RETROFIT UNCHANGED {existing_status.root}: already strict-valid "
                f"and fresh; registry {finalization.registration.action}; "
                f"lock {finalization.lock.action}; {hooks_summary}; no agent needed"
            )
            _print_retrofit_next_steps(existing_status.root)
            return 0
        if args.agent != "codex":
            raise CtxError(
                "retrofit.agent-unsupported",
                f"no guarded adapter is installed for agent {args.agent!r}; use --prompt",
                exit_code=1,
            )
        result = run_agent_retrofit(
            target,
            dry_run=args.dry_run,
            finalize=None if args.dry_run else finalize_retrofit,
            progress=_retrofit_progress,
        )
        _render_validation(result.validation)
        if not result.validation.valid:
            return 3 if result.validation.unsafe else 1
        if args.dry_run:
            operation = "RETROFIT REVIEW" if args.review else "RETROFIT DRY RUN"
            print(
                f"{operation} {result.root}: "
                f"{len(result.proposed_manifests)} manifest(s) proposed; "
                "no project files changed"
            )
            if result.agent_summary.strip():
                print(f"Agent summary: {_safe_display(result.agent_summary)}")
            if result.plan_id is not None:
                print(f"Review exact proposal: ctx retrofit --show-plan {result.plan_id}")
                review_required = any(
                    item.disposition == "unresolved" for item in result.coverage
                ) or any(
                    item.status == "review-required" for item in result.conflicts
                )
                if review_required:
                    print(
                        "Apply blocked: resolve every unresolved area and "
                        "review-required conflict, then rerun the dry run."
                    )
                else:
                    no_hooks = " --no-hooks" if args.no_hooks else ""
                    print(
                        f"Apply exact proposal: ctx retrofit --apply "
                        f"{result.plan_id}{no_hooks}"
                    )
            return 0
        if not isinstance(result.finalization, RetrofitLifecycleResult):
            raise CtxError(
                "retrofit.lifecycle-incomplete",
                "retrofit manifests validated but lifecycle finalization did not complete",
                exit_code=4,
            )
        registration = result.finalization.registration
        lock = result.finalization.lock
        hooks_summary = _retrofit_hooks_summary(result.finalization)
        print(
            f"RETROFIT COMPLETE {result.root}: "
            f"{len(result.created_manifests)} manifest(s) created; "
            f"registry {registration.action}; lock {lock.action}; {hooks_summary}"
        )
        if result.agent_summary.strip():
            print(f"Agent summary: {_safe_display(result.agent_summary)}")
        _print_retrofit_next_steps(result.root)
        return 0
    if args.command == "hook":
        payload = read_hook_input(sys.stdin.buffer)
        if args.hook_command == "codex-prompt":
            _write_json(codex_prompt_output(payload))
        elif args.hook_command == "codex-stop":
            _write_json(codex_stop_output(payload))
        else:  # pragma: no cover - argparse enforces the adapter set
            raise CtxError("cli.invalid", "unsupported hook adapter", exit_code=1)
        return 0
    if args.command == "integrate":
        if args.integration_command != "codex":  # pragma: no cover - argparse enforced
            raise CtxError("cli.invalid", "unsupported integration", exit_code=1)
        result = install_codex_hooks(
            project=None if args.project is None else Path(args.project),
            user=args.user,
        )
        print(f"{result.action} Codex hooks at {result.path}")
        scope = "project" if result.scope == "project" else "user-wide"
        print(
            f"Codex CLI/TUI: run /hooks and review and trust the {scope} hooks."
        )
        if result.scope == "project":
            quoted_root = shlex.quote(str(result.path.parent.parent))
            print(
                "Codex desktop: /hooks is not available; run "
                f"ctx hydrate --from {quoted_root} --task 'Map this project' immediately."
            )
        else:
            print(
                "Codex desktop: /hooks is not available; explicit ctx hydrate "
                "works immediately inside any ctx project."
            )
        return 0
    raise CtxError("cli.invalid", "unsupported command", exit_code=1)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["--help"]
    elif arguments[0] == "help":
        if len(arguments) == 1:
            arguments = ["--help"]
        elif len(arguments) == 2:
            arguments = [arguments[1], "--help"]
        else:
            arguments = [arguments[1], *arguments[2:], "--help"]
    elif len(arguments) >= 2 and arguments[1] == "help":
        arguments = [arguments[0], "--help", *arguments[2:]]
    if len(arguments) >= 2 and arguments[:2] == ["retrofit", "prompt"]:
        arguments[1:2] = ["--prompt"]
    if len(arguments) >= 2 and arguments[:2] == ["retrofit", "review"]:
        arguments[1:2] = ["--review", "--dry-run"]
    if len(arguments) >= 2 and arguments[:2] == ["reconcile", "prompt"]:
        arguments[1:2] = ["--prompt"]
    if len(arguments) >= 2 and arguments[:2] == ["reconcile", "inspect"]:
        arguments[1:2] = ["--inspect"]
    if len(arguments) >= 2 and arguments[:2] == ["reconcile", "acknowledge"]:
        arguments[1:2] = ["--acknowledge-node"]
    if len(arguments) >= 2 and arguments[:2] == ["reconcile", "complete"]:
        arguments[1:2] = ["--complete-run"]
    if len(arguments) >= 2 and arguments[:2] == ["node", "init"]:
        del arguments[1]
    if arguments and arguments[0] == "use":
        arguments[0] = "hydrate"
        arguments = ["--task" if value == "--for" else value for value in arguments]
    wants_json = "--json" in arguments
    executable = Path(sys.argv[0]).name
    program = "context-hydrate" if executable == "context-hydrate" else "ctx"
    parser = build_parser(prog=program)
    try:
        args = parser.parse_args(arguments)
        return _execute(args)
    except CtxError as exc:
        if wants_json:
            _write_json(_error_json(exc))
        else:
            print(_safe_display(f"ERROR {exc.code}: {exc.message}"), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        error = CtxError("operation.interrupted", "operation interrupted", exit_code=4)
        if wants_json:
            _write_json(_error_json(error))
        else:
            print(_safe_display(f"ERROR {error.code}: {error.message}"), file=sys.stderr)
        return error.exit_code
    except Exception as exc:  # pragma: no cover - final user-facing safety net
        error = CtxError("internal.error", f"unexpected failure: {exc}", exit_code=4)
        if wants_json:
            _write_json(_error_json(error))
        else:
            print(_safe_display(f"ERROR {error.code}: {error.message}"), file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
