from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.freshness import project_status, seal_freshness
from ctx.reconciliation import render_reconcile_prompt


class ItemArtifactEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.root = self.base / "item-evidence"
        self.shared = self.root / "shared"
        self.consumer = self.root / "consumer"
        self.leaf = self.consumer / "leaf"
        self.shared.mkdir(parents=True)
        self.leaf.mkdir(parents=True)

        self.files = {
            "consumer-pattern": self.shared / "pattern.txt",
            "consumer-invariant": self.shared / "invariant.txt",
            "consumer-decision": self.shared / "decision.txt",
            "other-pattern": self.shared / "unrelated.txt",
        }
        for item_id, path in self.files.items():
            path.write_text(f"{item_id} evidence bytes\n", encoding="utf-8")

        self._write_manifest(
            self.root,
            """version: 1
project:
  id: item-evidence
  name: Item Evidence
  aliases: []
node:
  id: root
  name: Item Evidence Root
""",
        )
        self._write_manifest(
            self.shared,
            """version: 1
node:
  id: shared
  name: Shared Evidence
""",
        )
        self._write_manifest(
            self.consumer,
            """version: 1
node:
  id: consumer
  name: Evidence Consumer
artifacts:
  - path: ../shared/pattern.txt
    role: SELECTED_PATTERN_EVIDENCE_ROLE
  - path: ../shared/invariant.txt
    role: MANDATORY_INVARIANT_EVIDENCE_ROLE
  - path: ../shared/decision.txt
    role: MANDATORY_DECISION_EVIDENCE_ROLE
  - path: ../shared/unrelated.txt
    role: UNRELATED_PATTERN_EVIDENCE_ROLE
items:
  - id: consumer-pattern
    kind: pattern
    title: Consumer pattern
    summary: Reusable behavior supported by pattern evidence.
    artifacts: [../shared/pattern.txt]
  - id: consumer-invariant
    kind: invariant
    title: Consumer invariant
    summary: Constraint supported by invariant evidence.
    artifacts: [../shared/invariant.txt]
  - id: consumer-decision
    kind: decision
    title: Consumer decision
    summary: Durable choice supported by decision evidence.
    artifacts: [../shared/decision.txt]
    reason: The evidence documents the current durable choice.
  - id: other-pattern
    kind: pattern
    title: Other pattern
    summary: Unrelated reusable behavior.
    artifacts: [../shared/unrelated.txt]
""",
        )
        self._write_manifest(
            self.leaf,
            """version: 1
node:
  id: leaf
  name: Consumer Leaf
""",
        )

    def run_ctx(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CTX_HOME"] = str(self.ctx_home)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=self.base,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def hydrate_item_json(self, item_id: str) -> dict[str, object]:
        result = self.run_ctx(
            "hydrate",
            f"ctx://item-evidence/consumer#{item_id}",
            "--from",
            str(self.root),
            "--json",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_exact_fragment_expands_only_selected_item_evidence(self) -> None:
        for selected_id, selected_path, selected_role in (
            (
                "consumer-pattern",
                "../shared/pattern.txt",
                "SELECTED_PATTERN_EVIDENCE_ROLE",
            ),
            (
                "consumer-invariant",
                "../shared/invariant.txt",
                "MANDATORY_INVARIANT_EVIDENCE_ROLE",
            ),
            (
                "consumer-decision",
                "../shared/decision.txt",
                "MANDATORY_DECISION_EVIDENCE_ROLE",
            ),
        ):
            with self.subTest(item=selected_id):
                payload = self.hydrate_item_json(selected_id)
                node = next(
                    value
                    for value in payload["nodes"]
                    if value["uri"] == "ctx://item-evidence/consumer"
                )
                self.assertEqual(
                    [artifact["path"] for artifact in node["artifacts"]],
                    [selected_path],
                )
                items = {item["id"]: item for item in node["items"]}
                self.assertEqual(items[selected_id]["artifacts"], [selected_path])
                for item_id, item in items.items():
                    if item_id != selected_id:
                        self.assertNotIn("artifacts", item)

                markdown = self.run_ctx(
                    "hydrate",
                    f"ctx://item-evidence/consumer#{selected_id}",
                    "--from",
                    str(self.root),
                )
                self.assertEqual(
                    markdown.returncode, 0, markdown.stdout + markdown.stderr
                )
                self.assertIn("Evidence artifacts:", markdown.stdout)
                self.assertIn(str(self.files[selected_id].resolve()), markdown.stdout)
                self.assertIn(selected_role, markdown.stdout)
                self.assertNotIn("Pattern artifacts:", markdown.stdout)
                for other_id, other_path in self.files.items():
                    if other_id != selected_id:
                        self.assertNotIn(str(other_path.resolve()), markdown.stdout)

    def test_full_node_keeps_all_evidence_while_ancestors_stay_compact(self) -> None:
        full = self.run_ctx("hydrate", "--from", str(self.consumer), "--json")
        self.assertEqual(full.returncode, 0, full.stdout + full.stderr)
        full_node = json.loads(full.stdout)["nodes"][-1]
        self.assertEqual(len(full_node["artifacts"]), 4)
        self.assertTrue(
            all("artifacts" in item for item in full_node["items"]),
            full_node["items"],
        )

        nested = self.run_ctx("hydrate", "--from", str(self.leaf), "--json")
        self.assertEqual(nested.returncode, 0, nested.stdout + nested.stderr)
        ancestor = next(
            node
            for node in json.loads(nested.stdout)["nodes"]
            if node["uri"] == "ctx://item-evidence/consumer"
        )
        self.assertEqual(ancestor["detail"], "ancestor")
        self.assertEqual(ancestor["artifacts"], [])
        self.assertTrue(
            all("artifacts" not in item for item in ancestor["items"]),
            ancestor["items"],
        )

    def test_show_uses_kind_neutral_item_evidence_label(self) -> None:
        shown = self.run_ctx("show", str(self.consumer))
        self.assertEqual(shown.returncode, 0, shown.stdout + shown.stderr)
        self.assertIn("Evidence artifacts:", shown.stdout)
        self.assertNotIn("Pattern artifacts:", shown.stdout)

    def test_reconciliation_inspection_maps_items_to_artifact_roles(self) -> None:
        sealed = seal_freshness(self.root)
        self.assertTrue(sealed.status.fresh)
        self.files["consumer-invariant"].write_text(
            "changed invariant evidence only\n", encoding="utf-8"
        )
        status = project_status(self.root)
        states = {node.uri: node.state for node in status.nodes}
        self.assertEqual(states["ctx://item-evidence/shared"], "stale")
        self.assertEqual(states["ctx://item-evidence/consumer"], "stale")

        prompt = render_reconcile_prompt(status, Path("/snapshot"))
        payload_line = next(
            line[4:] for line in prompt.splitlines() if line.startswith("    {")
        )
        payload = json.loads(payload_line)
        consumer = next(
            record
            for record in payload["reviewable_manifests"]
            if record["uri"] == "ctx://item-evidence/consumer"
        )
        artifact = next(
            record
            for record in consumer["artifacts"]
            if record["path"] == "../shared/invariant.txt"
        )
        self.assertEqual(artifact["project_path"], "shared/invariant.txt")
        self.assertEqual(
            artifact["role"], "MANDATORY_INVARIANT_EVIDENCE_ROLE"
        )
        self.assertEqual(artifact["referenced_by"], ["consumer-invariant"])
        invariant = next(
            record
            for record in consumer["item_evidence"]
            if record["id"] == "consumer-invariant"
        )
        self.assertEqual(invariant["kind"], "invariant")
        self.assertEqual(invariant["artifacts"], ["../shared/invariant.txt"])
        self.assertIn(
            "Every item artifact is an evidence reference", prompt
        )
        self.assertIn("top-level artifact with a precise role", prompt)
        self.assertNotIn("changed invariant evidence only", prompt)

    @staticmethod
    def _write_manifest(directory: Path, content: str) -> None:
        context = directory / ".ctx"
        context.mkdir()
        (context / "context.yaml").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
