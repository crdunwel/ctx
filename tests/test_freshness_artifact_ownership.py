from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx.freshness import project_status, seal_freshness


class SharedArtifactFreshnessTests(unittest.TestCase):
    def test_cross_scope_artifact_stales_physical_owner_and_declaring_node(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temporary:
            temporary = Path(raw_temporary)
            root = temporary / "artifact-ownership"
            shared = root / "shared"
            consumer = root / "consumer"
            shared.mkdir(parents=True)
            consumer.mkdir()

            self._write_manifest(
                root,
                """version: 1
project:
  id: artifact-ownership
  name: Artifact Ownership
  aliases: []
node:
  id: root
  name: Artifact Ownership
""",
            )
            self._write_manifest(
                shared,
                """version: 1
node:
  id: shared
  name: Shared Schema Owner
""",
            )
            self._write_manifest(
                consumer,
                """version: 1
node:
  id: consumer
  name: Schema Consumer
artifacts:
  - path: ../shared/schema.json
    role: Canonical schema consumed across this semantic boundary.
items:
  - id: schema-must-remain-compatible
    kind: invariant
    title: Shared schema compatibility
    summary: Consumers must remain compatible with the canonical shared schema.
    artifacts: [../shared/schema.json]
  - id: canonical-schema-source
    kind: decision
    title: Canonical schema source
    summary: The shared schema file is the authoritative contract source.
    artifacts: [../shared/schema.json]
    reason: A single source keeps consumers aligned.
""",
            )
            artifact = shared / "schema.json"
            artifact.write_text('{"version": 1}\n', encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {"CTX_HOME": str(temporary / "ctx-home")},
            ):
                sealed = seal_freshness(root)
                before = {node.uri: node for node in sealed.status.nodes}
                self.assertTrue(sealed.status.fresh)
                self.assertEqual(before["ctx://artifact-ownership/shared"].files, 1)
                self.assertEqual(before["ctx://artifact-ownership/consumer"].files, 1)

                artifact.write_text('{"version": 2}\n', encoding="utf-8")
                changed = project_status(root)

            after = {node.uri: node for node in changed.nodes}
            self.assertFalse(changed.fresh)
            self.assertEqual(after["ctx://artifact-ownership/shared"].state, "stale")
            self.assertEqual(after["ctx://artifact-ownership/consumer"].state, "stale")
            self.assertEqual(after["ctx://artifact-ownership"].state, "fresh")

    @staticmethod
    def _write_manifest(directory: Path, content: str) -> None:
        context = directory / ".ctx"
        context.mkdir()
        (context / "context.yaml").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
