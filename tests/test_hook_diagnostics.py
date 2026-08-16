from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctx.integration import diagnose_codex_hooks, install_codex_hooks
from ctx.services import init_project


class CodexHookDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        init_project(
            self.project,
            project_id="diagnostic-project",
            name="Diagnostic Project",
        )
        self.home = self.base / "home"
        self.home.mkdir()

    def test_missing_hooks_are_reported_without_writing(self) -> None:
        diagnosis = diagnose_codex_hooks(self.project, user_home=self.home)

        self.assertEqual(diagnosis.project.status, "missing")
        self.assertEqual(diagnosis.user.status, "missing")
        self.assertFalse(diagnosis.possible_duplicate_execution)
        self.assertFalse(diagnosis.trust_inspectable)
        self.assertFalse((self.project / ".codex").exists())
        self.assertFalse((self.home / ".codex").exists())
        payload = diagnosis.to_dict()
        json.dumps(payload)
        self.assertFalse(payload["trust"]["inspectable"])
        self.assertTrue(
            any("Explicit ctx commands work immediately" in item for item in diagnosis.recommendations)
        )
        self.assertTrue(
            any("Codex CLI/TUI" in item for item in diagnosis.recommendations)
        )
        self.assertTrue(
            any("desktop has no documented /hooks" in item for item in diagnosis.recommendations)
        )

    def test_canonical_and_noncanonical_regular_files_are_distinguished(self) -> None:
        install_codex_hooks(project=self.project)
        user_target = self.home / ".codex" / "hooks.json"
        user_target.parent.mkdir()
        user_target.write_bytes(b"this is deliberately not parsed as JSON\n")

        diagnosis = diagnose_codex_hooks(self.project, user_home=self.home)

        self.assertEqual(diagnosis.project.status, "canonical")
        self.assertEqual(diagnosis.user.status, "noncanonical")
        self.assertFalse(diagnosis.possible_duplicate_execution)
        self.assertEqual(
            user_target.read_bytes(),
            b"this is deliberately not parsed as JSON\n",
        )

    def test_hook_file_symlink_is_unsafe_and_is_not_followed(self) -> None:
        outside = self.base / "outside-hooks.json"
        outside.write_bytes(b'{"sensitive":"unchanged"}\n')
        target = self.project / ".codex" / "hooks.json"
        target.parent.mkdir()
        target.symlink_to(outside)

        diagnosis = diagnose_codex_hooks(self.project, user_home=self.home)

        self.assertEqual(diagnosis.project.status, "unsafe")
        self.assertIn("cannot be a symlink", diagnosis.project.detail)
        self.assertEqual(outside.read_bytes(), b'{"sensitive":"unchanged"}\n')

    def test_codex_directory_symlink_is_unsafe_and_is_not_followed(self) -> None:
        outside = self.base / "outside-codex"
        outside.mkdir()
        (outside / "hooks.json").write_bytes(b"outside\n")
        (self.project / ".codex").symlink_to(outside, target_is_directory=True)

        diagnosis = diagnose_codex_hooks(self.project, user_home=self.home)

        self.assertEqual(diagnosis.project.status, "unsafe")
        self.assertIn("cannot be a symlink", diagnosis.project.detail)
        self.assertEqual((outside / "hooks.json").read_bytes(), b"outside\n")

    def test_user_and_project_canonical_hooks_warn_about_possible_duplicate(self) -> None:
        install_codex_hooks(project=self.project)
        with patch.dict(os.environ, {"HOME": str(self.home)}, clear=False):
            install_codex_hooks(user=True)

        diagnosis = diagnose_codex_hooks(self.project, user_home=self.home)

        self.assertEqual(diagnosis.project.status, "canonical")
        self.assertEqual(diagnosis.user.status, "canonical")
        self.assertTrue(diagnosis.possible_duplicate_execution)
        self.assertTrue(
            any("possible duplicate execution" in item for item in diagnosis.recommendations)
        )


if __name__ == "__main__":
    unittest.main()
