from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctx.freshness import project_status, seal_freshness, seal_freshness_subset
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


if __name__ == "__main__":
    unittest.main()
