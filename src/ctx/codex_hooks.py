from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .diagnostics import CtxError, NotFoundError
from .discovery import discover_ancestry
from .freshness import LockResult, seal_freshness_subset
from .hydration import hydrate
from .runs import (
    RunNodeChange,
    RunRecord,
    attach_turn,
    begin_run,
    compare_run,
    completion_is_current,
    current_run_fingerprints,
    find_run,
    load_run,
    mark_complete,
    mark_continuation,
    mark_incomplete_allowed,
    record_acknowledgement,
    run_path_changes,
    run_uncovered_changes,
)
from .uri import ContextUri, parse_ctx_uri


MAX_HOOK_INPUT_BYTES = 1_048_576
HOOK_HYDRATION_BUDGET = 6_000
RUN_MARKER = re.compile(r"(?m)^CTX_RECONCILE_RUN=([a-f0-9]{32})$")


@dataclass(frozen=True, slots=True)
class RunCompletion:
    run: RunRecord
    changes: tuple[RunNodeChange, ...]
    lock: LockResult | None


def read_hook_input(stream: BinaryIO) -> dict[str, Any]:
    raw = stream.read(MAX_HOOK_INPUT_BYTES + 1)
    if len(raw) > MAX_HOOK_INPUT_BYTES:
        raise CtxError("hook.input-too-large", "Codex hook input exceeds its safety limit", exit_code=1)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxError("hook.input-invalid", f"Codex hook input is not valid UTF-8 JSON: {exc}", exit_code=1) from exc
    if type(value) is not dict:
        raise CtxError("hook.input-invalid", "Codex hook input must be a JSON object", exit_code=1)
    return value


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if type(value) is not str or not value or len(value) > 64_000:
        raise CtxError("hook.input-invalid", f"Codex hook field {key!r} must be a bounded non-empty string", exit_code=1)
    return value


def _hook_warning(message: str) -> dict[str, Any]:
    return {"systemMessage": message}


def _run_context(run: RunRecord, hydrated: str) -> str:
    return (
        hydrated
        + "\nAutomatic ctx synchronization is active for this turn.\n"
        + f"CTX_RECONCILE_RUN={run.run_id}\n"
        + "The immutable pre-edit baseline has already been captured. If source "
        "changes, preserve durable meaning in the affected context manifest or "
        "explicitly acknowledge an implementation-only change when prompted. "
        "Do not call `ctx begin` again for this run.\n"
    )


def codex_prompt_output(payload: dict[str, Any]) -> dict[str, Any]:
    event = _required_string(payload, "hook_event_name")
    if event != "UserPromptSubmit":
        raise CtxError("hook.event-invalid", "expected a UserPromptSubmit hook event", exit_code=1)
    cwd = Path(_required_string(payload, "cwd"))
    prompt = _required_string(payload, "prompt")
    session_id = _required_string(payload, "session_id")
    turn_id = _required_string(payload, "turn_id")
    try:
        try:
            discover_ancestry(cwd)
        except NotFoundError:
            # A user-level hook is expected to run outside ctx projects too.
            return {}
        marker = RUN_MARKER.search(prompt)
        if marker is not None:
            candidate = load_run(marker.group(1), root=cwd)
            if candidate.status == "active" and candidate.continuation_count == 1:
                run = attach_turn(candidate, session_id=session_id, turn_id=turn_id)
            else:
                # A marker is a one-use Stop continuation capability, not a
                # durable handle that can reset future task baselines.
                run = begin_run(
                    cwd,
                    task=prompt,
                    session_id=session_id,
                    turn_id=turn_id,
                )
        else:
            run = begin_run(
                cwd,
                task=prompt,
                session_id=session_id,
                turn_id=turn_id,
            )
        packet = hydrate(
            from_path=cwd,
            task=prompt,
            budget=HOOK_HYDRATION_BUDGET,
        )
    except CtxError as exc:
        return _hook_warning(
            f"ctx prompt hydration unavailable ({exc.code}); run `ctx validate . --strict` for details"
        )
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": _run_context(run, packet.to_markdown()),
        }
    }


def _resolve_run_uri(run: RunRecord, reference: str) -> str:
    if reference.startswith("ctx://"):
        parsed = parse_ctx_uri(reference)
        if parsed.project_id != run.project_id:
            raise CtxError("run.project-mismatch", "reference belongs to another project", exit_code=1)
        return str(ContextUri(parsed.project_id, parsed.node_ids))
    candidate = Path(reference)
    if not candidate.is_absolute():
        candidate = run.project_root / candidate
    if candidate.exists() or candidate.is_symlink():
        ancestry = discover_ancestry(candidate)
        if ancestry.project_root != run.project_root:
            raise CtxError("run.project-mismatch", "reference belongs to another project", exit_code=1)
        return ancestry.current.uri
    raise CtxError(
        "run.reference-invalid",
        "run-scoped reconciliation references must be a local path or ctx:// URI",
        exit_code=1,
    )


def inspect_run(run: RunRecord, reference: str | None = None) -> dict[str, Any]:
    current = current_run_fingerprints(run.project_root)
    changes = compare_run(run, current=current)
    if reference is not None:
        selected = _resolve_run_uri(run, reference)
        changes = tuple(value for value in changes if value.uri == selected)
        if not changes:
            raise CtxError("run.node-unaffected", f"node is not affected in this run: {selected}", exit_code=1)
    acknowledgements = {value.uri: value for value in run.acknowledgements}
    uncovered = {
        value.uri
        for value in run_uncovered_changes(run, current=current, changes=changes)
    }
    path_changes, path_limitation = run_path_changes(run)
    return {
        "schema": "ctx-run-inspection/v1",
        "run_id": run.run_id,
        "project": {"id": run.project_id, "root": str(run.project_root)},
        "task_digest": run.task_digest,
        "status": run.status,
        "baseline": {
            "git_head": run.baseline_git_head,
            "preexisting_dirty_files": len(run.baseline_dirty_files),
            "limitation": run.baseline_limitation,
        },
        "changed_paths": [value.to_dict() for value in path_changes],
        "path_attribution_limitation": path_limitation,
        "inspection_commands": [
            shlex.join(
                [
                    "ctx",
                    "hydrate",
                    "--from",
                    str(run.starting_path),
                    "--task",
                    f"Review run {run.run_id}",
                ]
            ),
            shlex.join(["ctx", "validate", str(run.project_root), "--strict"]),
        ],
        "changes": [
            {
                **change.to_dict(),
                "acknowledged": change.uri in acknowledgements,
                "acknowledgement": (
                    None
                    if change.uri not in acknowledgements
                    else acknowledgements[change.uri].reason
                ),
                "acknowledgement_current": (
                    change.uri in acknowledgements
                    and acknowledgements[change.uri].fingerprint == current.get(change.uri)
                ),
                "baseline_state": run.baseline_node_states.get(change.uri),
                "covered": change.uri not in uncovered,
            }
            for change in changes
        ],
        "uncovered": sorted(uncovered),
    }


def acknowledge_run(run: RunRecord, reference: str, reason: str) -> RunRecord:
    return record_acknowledgement(run, _resolve_run_uri(run, reference), reason)


def complete_run(run: RunRecord) -> RunCompletion:
    run = load_run(run.run_id, root=run.project_root)
    snapshot = current_run_fingerprints(run.project_root)
    changes = compare_run(run, current=snapshot)
    uncovered = run_uncovered_changes(run, current=snapshot, changes=changes)
    if uncovered:
        listed = ", ".join(value.uri for value in uncovered[:8])
        preexisting = [
            value.uri
            for value in uncovered
            if run.baseline_node_states.get(value.uri) in {"stale", "context-changed"}
        ]
        if preexisting:
            raise CtxError(
                "run.preexisting-stale",
                "affected nodes were already stale before this run and cannot be "
                "silently sealed by it; review them with detached `ctx reconcile`: "
                + ", ".join(preexisting[:8]),
                exit_code=1,
            )
        raise CtxError(
            "run.reconciliation-incomplete",
            "affected source changes still need a durable manifest update or "
            f"implementation-only acknowledgement: {listed}",
            exit_code=1,
        )
    lock: LockResult | None = None
    if changes:
        lock = seal_freshness_subset(
            run.project_root,
            {value.uri for value in changes},
            expected_fingerprints={
                uri: (value.source, value.context) for uri, value in snapshot.items()
            },
        )
    if current_run_fingerprints(run.project_root) != snapshot:
        raise CtxError(
            "run.project-changed",
            "project changed while the run was being completed; inspect the run again",
            exit_code=4,
        )
    completed = mark_complete(run, snapshot)
    return RunCompletion(completed, changes, lock)


def _continuation_reason(run: RunRecord, changes: tuple[RunNodeChange, ...], *, problem: str | None = None) -> str:
    affected = ", ".join(value.uri for value in changes[:12]) or "current run"
    lines = [
        f"CTX_RECONCILE_RUN={run.run_id}",
        "ctx detected source or durable-context changes made during this turn.",
        f"Affected semantic nodes: {affected}",
        f"Run `ctx reconcile inspect --run {run.run_id}` and inspect current source plus the listed evidence.",
        "For each affected node, update its existing `.ctx/context.yaml` only when durable meaning changed. "
        f"Otherwise run `ctx reconcile acknowledge <affected-uri> --reason <reason> --run {run.run_id}`.",
        f"Then run `ctx validate . --strict` and `ctx reconcile complete --run {run.run_id}`.",
        "Continue this exact run; do not call `ctx begin`, start a nested reconciliation agent, or modify source merely to satisfy ctx.",
    ]
    if problem:
        lines.insert(3, f"Completion issue: {problem}")
    preexisting = [
        value.uri
        for value in changes
        if run.baseline_node_states.get(value.uri) in {"stale", "context-changed"}
    ]
    if preexisting:
        lines.insert(
            4,
            "These affected nodes were already non-fresh before this turn and will not be "
            "sealed by a run acknowledgement: " + ", ".join(preexisting[:8])
            + ". Review that pre-existing state separately with detached `ctx reconcile`.",
        )
    return "\n".join(lines)


def codex_stop_output(payload: dict[str, Any]) -> dict[str, Any]:
    event = _required_string(payload, "hook_event_name")
    if event != "Stop":
        raise CtxError("hook.event-invalid", "expected a Stop hook event", exit_code=1)
    cwd = Path(_required_string(payload, "cwd"))
    session_id = _required_string(payload, "session_id")
    turn_id = _required_string(payload, "turn_id")
    stop_hook_active = payload.get("stop_hook_active", False)
    if type(stop_hook_active) is not bool:
        raise CtxError("hook.input-invalid", "stop_hook_active must be a boolean", exit_code=1)
    run: RunRecord | None = None
    try:
        run = find_run(cwd, session_id=session_id, turn_id=turn_id)
        if run is None:
            return {}
        if completion_is_current(run):
            return {}
        snapshot = current_run_fingerprints(run.project_root)
        changes = compare_run(run, current=snapshot)
        if not changes:
            mark_complete(run, snapshot)
            return {}
        problem: str | None = None
        if not run_uncovered_changes(run, current=snapshot, changes=changes):
            try:
                complete_run(run)
                return {}
            except CtxError as exc:
                problem = f"{exc.code}; inspect with the listed ctx commands"
        if stop_hook_active or run.continuation_count >= 1:
            mark_incomplete_allowed(run)
            return _hook_warning(
                "ctx reconciliation remains incomplete after the single allowed "
                f"continuation for run {run.run_id}; the turn may stop, but `ctx status --check` "
                "will continue to report attention until reviewed."
            )
        mark_continuation(run)
        return {
            "decision": "block",
            "reason": _continuation_reason(run, changes, problem=problem),
        }
    except NotFoundError:
        return {}
    except CtxError as exc:
        if run is not None and not stop_hook_active and run.continuation_count < 1:
            try:
                mark_continuation(run)
                return {
                    "decision": "block",
                    "reason": _continuation_reason(
                        run,
                        (),
                        problem=f"{exc.code}; inspect with the listed ctx commands",
                    ),
                }
            except CtxError:
                pass
        if run is not None and (stop_hook_active or run.continuation_count >= 1):
            try:
                mark_incomplete_allowed(run)
            except CtxError:
                pass
        return _hook_warning(
            f"ctx Stop check unavailable ({exc.code}); run `ctx validate . --strict` "
            "and `ctx status --check` for details"
        )
