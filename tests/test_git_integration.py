from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.diagnostics import CtxError, UnsafePathError
from ctx.git_integration import install_git_pre_commit_hook
from ctx.services import init_project


class GitHookIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        init_project(self.project, project_id="git-hook-project", name="Git Hook Project")
        self._git(self.project, "init", "-q")

    def _git(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def _ctx(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=self.project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _commit_project(self) -> None:
        self._git(self.project, "config", "user.email", "ctx-tests@example.invalid")
        self._git(self.project, "config", "user.name", "ctx tests")
        self._git(self.project, "add", ".ctx/context.yaml")
        self._git(self.project, "commit", "-q", "-m", "initial context")

    def test_install_creates_executable_status_only_hook(self) -> None:
        result = install_git_pre_commit_hook(self.project)

        expected = self.project / ".git" / "hooks" / "pre-commit"
        self.assertEqual(result.action, "created")
        self.assertEqual(result.path, expected.resolve())
        self.assertEqual(result.project_root, self.project.resolve())
        self.assertFalse(result.blocking)
        content = result.path.read_text(encoding="utf-8")
        self.assertTrue(content.startswith("#!/bin/sh\n"))
        self.assertIn('ctx status "$project_root" --check', content)
        self.assertIn("Run: ctx reconcile", content)
        self.assertNotIn("\nctx reconcile", content)
        self.assertNotIn("git add", content)
        self.assertNotIn("git commit", content)
        self.assertTrue(result.path.stat().st_mode & stat.S_IXUSR)

    def test_cli_help_and_required_selector_are_explicit(self) -> None:
        help_result = self._ctx("integrate", "git", "--help")

        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--hooks", help_result.stdout)
        self.assertIn("--project PATH", help_result.stdout)
        self.assertIn("--block", help_result.stdout)
        self.assertIn("warning-only", help_result.stdout)
        self.assertIn("ctx status --check", help_result.stdout)
        self.assertIn("ctx reconcile", help_result.stdout)

        missing = self._ctx("integrate", "git")
        self.assertEqual(missing.returncode, 1)
        self.assertIn("--hooks", missing.stderr)

    def test_cli_installs_warning_hook_and_explains_boundaries(self) -> None:
        completed = self._ctx("integrate", "git", "--hooks")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("created Git pre-commit ctx hook", completed.stdout)
        self.assertIn("Mode: warning only", completed.stdout)
        self.assertIn("not staged blobs", completed.stdout)
        self.assertIn("run ctx reconcile", completed.stdout)
        self.assertIn("never invokes an agent", completed.stdout)
        self.assertTrue((self.project / ".git" / "hooks" / "pre-commit").exists())

    def test_install_is_byte_and_inode_idempotent(self) -> None:
        created = install_git_pre_commit_hook(self.project)
        before = created.path.read_bytes()
        identity = (created.path.stat().st_dev, created.path.stat().st_ino)

        repeated = install_git_pre_commit_hook(self.project / ".ctx")

        self.assertEqual(repeated.action, "unchanged")
        self.assertEqual(repeated.path.read_bytes(), before)
        self.assertEqual(
            (repeated.path.stat().st_dev, repeated.path.stat().st_ino),
            identity,
        )

    def test_existing_hook_is_preserved(self) -> None:
        target = self.project / ".git" / "hooks" / "pre-commit"
        original = b"#!/bin/sh\necho existing\n"
        target.write_bytes(original)
        target.chmod(0o755)

        with self.assertRaises(CtxError) as raised:
            install_git_pre_commit_hook(self.project)

        self.assertEqual(raised.exception.code, "git.hook-conflict")
        self.assertEqual(target.read_bytes(), original)

    def test_symlinked_hook_and_hooks_directory_are_rejected(self) -> None:
        target = self.project / ".git" / "hooks" / "pre-commit"
        outside = self.base / "outside-hook"
        outside.write_text("outside\n", encoding="utf-8")
        target.symlink_to(outside)

        with self.assertRaises(UnsafePathError) as hook_error:
            install_git_pre_commit_hook(self.project)
        self.assertEqual(hook_error.exception.code, "git.hook-symlink")
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")

        target.unlink()
        hooks = target.parent
        for sample in hooks.iterdir():
            sample.unlink()
        hooks.rmdir()
        outside_directory = self.base / "outside-hooks"
        outside_directory.mkdir()
        hooks.symlink_to(outside_directory, target_is_directory=True)

        with self.assertRaises(UnsafePathError) as directory_error:
            install_git_pre_commit_hook(self.project)
        self.assertEqual(
            directory_error.exception.code,
            "git.hooks-directory-symlink",
        )
        self.assertEqual(tuple(outside_directory.iterdir()), ())

    def test_configured_hooks_path_is_not_modified(self) -> None:
        shared = self.base / "shared-hooks"
        shared.mkdir()
        self._git(self.project, "config", "core.hooksPath", str(shared))

        with self.assertRaises(CtxError) as raised:
            install_git_pre_commit_hook(self.project)

        self.assertEqual(raised.exception.code, "git.hooks-path-configured")
        self.assertEqual(tuple(shared.iterdir()), ())

    def test_hook_checks_current_worktree_root_and_prints_reconcile_guidance(self) -> None:
        self._commit_project()
        result = install_git_pre_commit_hook(self.project, block=True)
        fake_bin = self.base / "bin"
        fake_bin.mkdir()
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CTX_HOOK_RECORD\"\n"
            "exit \"${CTX_HOOK_EXIT:-0}\"\n",
            encoding="utf-8",
        )
        fake_ctx.chmod(0o755)
        record = self.base / "record.txt"
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))
        environment["CTX_HOOK_RECORD"] = str(record)
        environment["CTX_HOOK_EXIT"] = "3"

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(
            record.read_text(encoding="utf-8").splitlines(),
            ["status", str(self.project.resolve()), "--check"],
        )
        self.assertIn("ctx reconcile", completed.stderr)
        self.assertIn("commit blocked", completed.stderr)

    def test_warning_hook_allows_stale_commit_after_guidance(self) -> None:
        result = install_git_pre_commit_hook(self.project)
        fake_bin = self.base / "warning-bin"
        fake_bin.mkdir()
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        fake_ctx.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertIn("ctx reconcile", completed.stderr)
        self.assertIn("warning only; commit allowed", completed.stderr)

    def test_fresh_hook_is_silent(self) -> None:
        self._commit_project()
        result = install_git_pre_commit_hook(self.project, block=True)
        fake_bin = self.base / "silent-bin"
        fake_bin.mkdir()
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text(
            "#!/bin/sh\necho FRESH\necho detail >&2\nexit 0\n",
            encoding="utf-8",
        )
        fake_ctx.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_common_hook_skips_worktree_without_ctx_manifest(self) -> None:
        result = install_git_pre_commit_hook(self.project, block=True)
        (self.project / ".ctx" / "context.yaml").unlink()
        environment = os.environ.copy()
        git = shutil.which("git")
        assert git is not None
        environment["PATH"] = os.pathsep.join((str(Path(git).parent), "/bin"))

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")

    def test_blocking_hook_rejects_deletion_of_tracked_root_manifest(self) -> None:
        self._commit_project()
        result = install_git_pre_commit_hook(self.project, block=True)
        (self.project / ".ctx" / "context.yaml").unlink()
        self._git(self.project, "add", "-u", ".ctx/context.yaml")

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("tracked root .ctx/context.yaml is missing", completed.stderr)
        self.assertIn("ctx reconcile", completed.stderr)
        self.assertIn("commit blocked", completed.stderr)

    def test_warning_hook_reports_fresh_status_with_unstaged_ctx_changes(self) -> None:
        self._git(self.project, "config", "user.email", "ctx-tests@example.invalid")
        self._git(self.project, "config", "user.name", "ctx tests")
        lock = self.project / ".ctx" / "lock.json"
        lock.write_text('{"version": "old"}\n', encoding="utf-8")
        self._git(self.project, "add", ".ctx")
        self._git(self.project, "commit", "-q", "-m", "initial context")
        result = install_git_pre_commit_hook(self.project)
        lock.write_text('{"version": "reconciled"}\n', encoding="utf-8")

        fake_bin = self.base / "fresh-bin"
        fake_bin.mkdir()
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_ctx.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))
        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertIn("context changes are not staged", completed.stderr)
        self.assertIn("git-add the intended .ctx files", completed.stderr)
        self.assertIn("warning only; commit allowed", completed.stderr)

    def test_blocking_hook_rejects_unstaged_tracked_source_before_status(self) -> None:
        self._commit_project()
        source = self.project / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        self._git(self.project, "add", "app.py")
        self._git(self.project, "commit", "-q", "-m", "add source")
        result = install_git_pre_commit_hook(self.project, block=True)
        source.write_text("VALUE = 2\n", encoding="utf-8")

        fake_bin = self.base / "tracked-bin"
        fake_bin.mkdir()
        marker = self.base / "tracked-status-ran"
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text(
            "#!/bin/sh\ntouch \"$CTX_STATUS_MARKER\"\nexit 0\n",
            encoding="utf-8",
        )
        fake_ctx.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))
        environment["CTX_STATUS_MARKER"] = str(marker)

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertFalse(marker.exists())
        self.assertIn("cannot verify partial staging or untracked files", completed.stderr)
        self.assertIn("Stage or stash", completed.stderr)

    def test_blocking_hook_rejects_untracked_source_before_status(self) -> None:
        self._commit_project()
        result = install_git_pre_commit_hook(self.project, block=True)
        (self.project / "new.py").write_text("NEW = True\n", encoding="utf-8")

        fake_bin = self.base / "untracked-bin"
        fake_bin.mkdir()
        marker = self.base / "untracked-status-ran"
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text(
            "#!/bin/sh\ntouch \"$CTX_STATUS_MARKER\"\nexit 0\n",
            encoding="utf-8",
        )
        fake_ctx.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))
        environment["CTX_STATUS_MARKER"] = str(marker)

        completed = subprocess.run(
            [str(result.path)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertFalse(marker.exists())
        self.assertIn("cannot verify partial staging or untracked files", completed.stderr)

    def test_blocking_mode_does_not_replace_warning_hook(self) -> None:
        warning = install_git_pre_commit_hook(self.project)
        original = warning.path.read_bytes()

        with self.assertRaises(CtxError) as raised:
            install_git_pre_commit_hook(self.project, block=True)

        self.assertEqual(raised.exception.code, "git.hook-conflict")
        self.assertEqual(warning.path.read_bytes(), original)

    def test_linked_worktree_reuses_common_hook_safely(self) -> None:
        self._commit_project()
        linked = self.base / "linked"
        self._git(self.project, "worktree", "add", "-q", "-b", "linked", str(linked))

        linked_result = install_git_pre_commit_hook(linked)
        main_result = install_git_pre_commit_hook(self.project)

        self.assertEqual(linked_result.action, "created")
        self.assertEqual(main_result.action, "unchanged")
        self.assertEqual(linked_result.path, main_result.path)
        self.assertEqual(linked_result.git_common_dir, (self.project / ".git").resolve())
        content = linked_result.path.read_text(encoding="utf-8")
        self.assertNotIn(str(linked.resolve()), content)
        self.assertNotIn(str(self.project.resolve()), content)

        fake_bin = self.base / "linked-bin"
        fake_bin.mkdir()
        fake_ctx = fake_bin / "ctx"
        fake_ctx.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CTX_HOOK_RECORD\"\nexit 0\n",
            encoding="utf-8",
        )
        fake_ctx.chmod(0o755)
        record = self.base / "linked-record.txt"
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join((str(fake_bin), environment["PATH"]))
        environment["CTX_HOOK_RECORD"] = str(record)
        completed = subprocess.run(
            [str(linked_result.path)],
            cwd=linked,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            record.read_text(encoding="utf-8").splitlines(),
            ["status", str(linked.resolve()), "--check"],
        )


if __name__ == "__main__":
    unittest.main()
