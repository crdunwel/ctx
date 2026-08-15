from __future__ import annotations

import errno
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctx.diagnostics import CtxError, UnsafePathError
from ctx.integration import install_codex_hooks, remove_created_codex_hooks
from ctx.services import init_project


EXPECTED_HOOKS = {
    "description": "Automatic .ctx hydration and reconciliation.",
    "hooks": {
        "UserPromptSubmit": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "ctx hook codex-prompt",
                        "timeout": 15,
                        "additionalContextLimit": 6000,
                        "statusMessage": "Hydrating project context",
                    }
                ]
            }
        ],
        "Stop": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "ctx hook codex-stop",
                        "timeout": 30,
                        "statusMessage": "Checking .ctx freshness",
                    }
                ]
            }
        ],
    },
}


class CodexHookIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        init_project(
            self.project,
            project_id="integration-project",
            name="Integration Project",
        )

    def test_project_install_creates_exact_canonical_hooks(self) -> None:
        result = install_codex_hooks(project=self.project)

        expected_path = self.project.resolve() / ".codex" / "hooks.json"
        self.assertEqual(result.action, "created")
        self.assertEqual(result.path, expected_path)
        self.assertEqual(result.scope, "project")
        self.assertEqual(result.project_root, self.project.resolve())
        raw = expected_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(json.loads(raw), EXPECTED_HOOKS)
        self.assertEqual(
            raw,
            (json.dumps(EXPECTED_HOOKS, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
                "utf-8"
            ),
        )

    def test_project_install_is_byte_idempotent(self) -> None:
        created = install_codex_hooks(project=self.project)
        before = created.path.read_bytes()

        repeated = install_codex_hooks(project=self.project / ".ctx")

        self.assertEqual(repeated.action, "unchanged")
        self.assertEqual(repeated.path, created.path)
        self.assertEqual(repeated.path.read_bytes(), before)

    def test_project_install_refuses_differing_existing_file(self) -> None:
        target = self.project / ".codex" / "hooks.json"
        target.parent.mkdir()
        original = b'{"hooks":{"Existing":[]}}\n'
        target.write_bytes(original)

        with self.assertRaises(CtxError) as raised:
            install_codex_hooks(project=self.project)

        self.assertEqual(raised.exception.code, "integration.hooks-conflict")
        self.assertEqual(target.read_bytes(), original)

    def test_project_install_rejects_symlinked_target_and_parent(self) -> None:
        outside = self.base / "outside.json"
        outside.write_text("outside\n", encoding="utf-8")
        target = self.project / ".codex" / "hooks.json"
        target.parent.mkdir()
        target.symlink_to(outside)

        with self.assertRaises(UnsafePathError) as target_error:
            install_codex_hooks(project=self.project)
        self.assertEqual(target_error.exception.code, "integration.hooks-symlink")
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")

        target.unlink()
        target.parent.rmdir()
        outside_directory = self.base / "outside-directory"
        outside_directory.mkdir()
        target.parent.symlink_to(outside_directory, target_is_directory=True)

        with self.assertRaises(UnsafePathError) as parent_error:
            install_codex_hooks(project=self.project)
        self.assertEqual(
            parent_error.exception.code,
            "integration.codex-directory-symlink",
        )
        self.assertEqual(tuple(outside_directory.iterdir()), ())

    def test_parent_fsync_failure_removes_new_hook_and_codex_directory(self) -> None:
        with patch(
            "ctx.integration.os.fsync",
            side_effect=(None, OSError(errno.EIO, "simulated parent fsync failure")),
        ):
            with self.assertRaises(CtxError) as raised:
                install_codex_hooks(project=self.project)

        self.assertEqual(raised.exception.code, "integration.hooks-write-failed")
        self.assertFalse((self.project / ".codex").exists())

    def test_rollback_refuses_identical_replacement_with_new_inode(self) -> None:
        result = install_codex_hooks(project=self.project)
        original = result.path.read_bytes()
        original_identity = (result.path.stat().st_dev, result.path.stat().st_ino)
        replacement = result.path.with_name("replacement.json")
        replacement.write_bytes(original)
        os.replace(replacement, result.path)
        replacement_identity = (result.path.stat().st_dev, result.path.stat().st_ino)
        self.assertNotEqual(replacement_identity, original_identity)

        with self.assertRaises(CtxError) as raised:
            remove_created_codex_hooks(result)

        self.assertEqual(raised.exception.code, "integration.rollback-failed")
        self.assertEqual(result.path.read_bytes(), original)
        self.assertEqual(
            (result.path.stat().st_dev, result.path.stat().st_ino),
            replacement_identity,
        )

    def test_rollback_reports_deleted_created_hook(self) -> None:
        result = install_codex_hooks(project=self.project)
        result.path.unlink()

        with self.assertRaises(CtxError) as raised:
            remove_created_codex_hooks(result)

        self.assertEqual(raised.exception.code, "integration.rollback-failed")
        self.assertFalse(result.path.exists())
        self.assertFalse(result.path.parent.exists())

    def test_user_install_uses_home_not_ctx_home(self) -> None:
        home = self.base / "isolated-home"
        home.mkdir()
        unrelated_ctx_home = self.base / "ctx-home"
        with patch.dict(
            os.environ,
            {"HOME": str(home), "CTX_HOME": str(unrelated_ctx_home)},
            clear=False,
        ):
            result = install_codex_hooks(user=True)
            repeated = install_codex_hooks(user=True)

        expected_path = home / ".codex" / "hooks.json"
        self.assertEqual(result.action, "created")
        self.assertEqual(repeated.action, "unchanged")
        self.assertEqual(result.path, expected_path)
        self.assertEqual(result.scope, "user")
        self.assertIsNone(result.project_root)
        self.assertEqual(json.loads(expected_path.read_bytes()), EXPECTED_HOOKS)
        self.assertFalse(unrelated_ctx_home.exists())

    def test_user_and_project_targets_are_mutually_exclusive(self) -> None:
        with self.assertRaises(CtxError) as raised:
            install_codex_hooks(project=self.project, user=True)
        self.assertEqual(raised.exception.code, "integration.mode-conflict")
        self.assertFalse((self.project / ".codex").exists())


if __name__ == "__main__":
    unittest.main()
