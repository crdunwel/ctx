from __future__ import annotations

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ctx.codex_hooks import complete_run
from ctx.diagnostics import CtxError, UnsafePathError
from ctx.freshness import project_status, seal_freshness
from ctx.runs import (
    attach_turn,
    begin_run,
    compare_run,
    find_run,
    load_run,
    mark_continuation,
    record_acknowledgement,
    run_uncovered_changes,
)
from ctx.services import init_project


class RunBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.root = self.base / "project"
        self.root.mkdir()
        self.source = self.root / "app.py"
        self.source.write_text("SECRET_SOURCE_CANARY = 1\n", encoding="utf-8")
        init_project(self.root, project_id="run-project", name="Run Project")
        seal_freshness(self.root)
        self.environment = patch.dict(os.environ, {"CTX_HOME": str(self.ctx_home)}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_begin_is_idempotent_for_one_turn_and_stores_hashes_not_source(self) -> None:
        first = begin_run(
            self.root,
            task="Change the constant",
            session_id="session",
            turn_id="turn",
        )
        repeated = begin_run(
            self.root,
            task="A replacement task must not reset the baseline",
            session_id="session",
            turn_id="turn",
        )
        self.assertEqual(repeated.run_id, first.run_id)
        self.assertEqual(repeated.task_digest, first.task_digest)
        self.assertNotIn(b"Change the constant", first.path.read_bytes())
        self.assertFalse(first.path.is_relative_to(self.root))
        self.assertNotIn(b"SECRET_SOURCE_CANARY", first.path.read_bytes())

        self.source.write_text("SECRET_SOURCE_CANARY = 2\n", encoding="utf-8")
        changes = compare_run(first)
        self.assertEqual([value.uri for value in changes], ["ctx://run-project"])
        self.assertTrue(changes[0].source_changed)
        self.assertFalse(changes[0].context_changed)

    def test_continuation_attaches_turn_without_resetting_baseline(self) -> None:
        run = begin_run(
            self.root,
            task="Change source",
            session_id="session",
            turn_id="turn-1",
        )
        baseline = run.baseline_nodes
        self.source.write_text("SECRET_SOURCE_CANARY = 2\n", encoding="utf-8")

        attached = attach_turn(
            mark_continuation(run),
            session_id="session",
            turn_id="turn-2",
        )

        self.assertEqual(attached.baseline_nodes, baseline)
        self.assertEqual(attached.turn_ids, ("turn-1", "turn-2"))
        self.assertEqual(load_run(run.run_id, root=self.root).baseline_nodes, baseline)
        found = find_run(self.root, session_id="session", turn_id="turn-2")
        self.assertIsNotNone(found)
        self.assertEqual(found.run_id, run.run_id)

    def test_concurrent_matching_hooks_converge_on_one_run(self) -> None:
        def start() -> str:
            return begin_run(
                self.root,
                task="Concurrent hook task",
                session_id="shared-session",
                turn_id="shared-turn",
            ).run_id

        with ThreadPoolExecutor(max_workers=2) as pool:
            run_ids = list(pool.map(lambda _value: start(), range(2)))

        self.assertEqual(run_ids[0], run_ids[1])
        self.assertEqual(len(list((self.ctx_home / "runs").glob("*/*.json"))), 1)

    def test_acknowledgement_is_invalidated_by_a_later_source_change(self) -> None:
        run = begin_run(
            self.root,
            task="Change source",
            session_id="session",
            turn_id="turn",
        )
        self.source.write_text("SECRET_SOURCE_CANARY = 2\n", encoding="utf-8")
        acknowledged = record_acknowledgement(
            run,
            "ctx://run-project",
            "Implementation-only constant change.",
        )
        self.assertEqual(run_uncovered_changes(acknowledged), ())

        self.source.write_text("SECRET_SOURCE_CANARY = 3\n", encoding="utf-8")

        current = load_run(run.run_id, root=self.root)
        self.assertEqual(
            [change.uri for change in run_uncovered_changes(current)],
            ["ctx://run-project"],
        )

    def test_preexisting_stale_state_in_same_node_is_not_sealed_by_run(self) -> None:
        preexisting = self.root / "preexisting.py"
        preexisting.write_text("PREEXISTING = True\n", encoding="utf-8")
        self.assertFalse(project_status(self.root).fresh)
        run = begin_run(
            self.root,
            task="Change the run-owned constant",
            session_id="session",
            turn_id="turn",
        )
        self.source.write_text("SECRET_SOURCE_CANARY = 2\n", encoding="utf-8")
        acknowledged = record_acknowledgement(
            run,
            "ctx://run-project",
            "Implementation-only constant change made during this run.",
        )

        try:
            complete_run(acknowledged)
        except CtxError:
            # Refusal is safe when a node-level lock cannot attribute only the
            # current run's edit. Successful completion must also preserve the
            # pre-turn stale state rather than bless it.
            pass

        self.assertFalse(project_status(self.root).fresh)

    def test_completion_rejects_a_change_after_its_sealed_snapshot(self) -> None:
        run = begin_run(
            self.root,
            task="Change source",
            session_id="session",
            turn_id="turn",
        )
        self.source.write_text("SECRET_SOURCE_CANARY = 2\n", encoding="utf-8")
        acknowledged = record_acknowledgement(
            run,
            "ctx://run-project",
            "Implementation-only constant change.",
        )

        from ctx import codex_hooks

        real_seal = codex_hooks.seal_freshness_subset

        def race_after_seal(*args: object, **kwargs: object):
            result = real_seal(*args, **kwargs)
            self.source.write_text("SECRET_SOURCE_CANARY = 3\n", encoding="utf-8")
            return result

        with patch("ctx.codex_hooks.seal_freshness_subset", side_effect=race_after_seal):
            with self.assertRaises(CtxError) as raised:
                complete_run(acknowledged)

        self.assertEqual(raised.exception.code, "run.project-changed")
        self.assertNotEqual(load_run(run.run_id, root=self.root).status, "complete")

    def test_runs_symlink_beneath_ctx_home_is_refused(self) -> None:
        self.ctx_home.mkdir()
        outside = self.base / "outside-runs"
        outside.mkdir()
        (self.ctx_home / "runs").symlink_to(outside, target_is_directory=True)

        with self.assertRaises(UnsafePathError):
            begin_run(
                self.root,
                task="Do not follow the runs symlink",
                session_id="session",
                turn_id="turn",
            )

        self.assertEqual(list(outside.rglob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
