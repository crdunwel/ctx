from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx import freshness
from ctx.diagnostics import CtxError
from ctx.freshness import (
    initialize_freshness,
    project_status,
    read_lock_bytes_no_follow,
    seal_freshness,
    seal_freshness_subset,
)
from ctx.services import init_node, init_project


class SelectiveFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        init_project(self.root, project_id="selective", name="Selective")
        self.left = self.root / "left"
        self.right = self.root / "right"
        self.left.mkdir()
        self.right.mkdir()
        init_node(self.left, node_id="left", name="Left")
        init_node(self.right, node_id="right", name="Right")
        self.left_source = self.left / "left.py"
        self.right_source = self.right / "right.py"
        self.left_source.write_text("LEFT = 1\n", encoding="utf-8")
        self.right_source.write_text("RIGHT = 1\n", encoding="utf-8")
        seal_freshness(self.root)

    def test_seals_only_reviewed_nodes(self) -> None:
        self.left_source.write_text("LEFT = 2\n", encoding="utf-8")
        self.right_source.write_text("RIGHT = 2\n", encoding="utf-8")

        result = seal_freshness_subset(self.root, {"ctx://selective/left"})
        self.assertEqual(result.content, result.path.read_bytes())

        states = {node.uri: node.state for node in result.status.nodes}
        self.assertEqual(states["ctx://selective/left"], "fresh")
        self.assertEqual(states["ctx://selective/right"], "stale")
        self.assertFalse(result.status.fresh)

        repeated = seal_freshness_subset(self.root, {"ctx://selective/left"})
        self.assertEqual(repeated.action, "unchanged")
        status = project_status(self.root)
        self.assertEqual(
            {node.uri: node.state for node in status.nodes}["ctx://selective/right"],
            "stale",
        )

    @unittest.skipIf(
        os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
        "requires no-follow opens",
    )
    def test_exact_lock_read_rejects_symlink_without_reading_target(self) -> None:
        lock = project_status(self.root).lock_path
        outside = Path(self.temporary.name) / "outside-lock.json"
        outside_content = b'{"outside":"must-not-be-consumed"}\n'
        outside.write_bytes(outside_content)
        lock.unlink()
        lock.symlink_to(outside)

        with self.assertRaises(CtxError) as raised:
            read_lock_bytes_no_follow(lock)

        self.assertEqual(raised.exception.code, "lock.symlink")
        self.assertEqual(outside.read_bytes(), outside_content)

    def test_initialization_does_not_overwrite_lock_that_appears(self) -> None:
        root = Path(self.temporary.name) / "initialization-race"
        root.mkdir()
        init_project(root, project_id="initialization-race", name="Initialization Race")
        (root / "app.py").write_text("READY = True\n", encoding="utf-8")
        initial = seal_freshness(root)
        lock = initial.path
        assert initial.content is not None
        concurrent = initial.content
        lock.unlink()
        seal = freshness.seal_freshness

        def create_before_seal(path: Path, **kwargs: object) -> object:
            lock.write_bytes(concurrent)
            return seal(path, **kwargs)

        with mock.patch.object(
            freshness,
            "seal_freshness",
            side_effect=create_before_seal,
        ):
            with self.assertRaises(CtxError) as raised:
                initialize_freshness(root)

        self.assertEqual(raised.exception.code, "lock.concurrent-change")
        self.assertEqual(lock.read_bytes(), concurrent)

    def test_selective_seal_does_not_overwrite_lock_changed_after_load(self) -> None:
        lock = project_status(self.root).lock_path
        concurrent = b'{"concurrent":true}\n'
        load = freshness._load_lock
        loads = 0

        def load_then_change(*args: object, **kwargs: object) -> object:
            nonlocal loads
            result = load(*args, **kwargs)
            loads += 1
            if loads == 1:
                lock.write_bytes(concurrent)
            return result

        with mock.patch.object(
            freshness,
            "_load_lock",
            side_effect=load_then_change,
        ):
            with self.assertRaises(CtxError) as raised:
                seal_freshness_subset(self.root, {"ctx://selective/left"})

        self.assertEqual(raised.exception.code, "lock.concurrent-change")
        self.assertEqual(lock.read_bytes(), concurrent)

    def test_oversized_replacement_is_rejected_before_touching_lock(self) -> None:
        lock = project_status(self.root).lock_path
        before = lock.read_bytes()

        with self.assertRaises(CtxError) as raised:
            freshness._replace_lock_bytes(
                lock,
                b"x" * (freshness.MAX_LOCK_BYTES + 1),
                expected_previous=before,
            )

        self.assertEqual(raised.exception.code, "lock.too-large")
        self.assertEqual(lock.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
