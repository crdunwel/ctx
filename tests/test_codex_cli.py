from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx.codex_cli import find_codex_executable
from ctx.diagnostics import CtxError


class CodexExecutableResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def executable(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path.resolve()

    def test_resolves_codex_from_path(self) -> None:
        executable = self.executable(self.base / "path-bin" / "codex")

        with mock.patch("ctx.codex_cli._macos_bundle_candidates", return_value=()):
            resolved = find_codex_executable(
                environment={"PATH": str(executable.parent)}
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.path, executable)
        self.assertEqual(resolved.source, "path")

    def test_path_wins_over_macos_chatgpt_bundle(self) -> None:
        path_executable = self.executable(self.base / "path-bin" / "codex")
        bundle = self.executable(
            self.base / "ChatGPT.app" / "Contents" / "Resources" / "codex"
        )

        with mock.patch(
            "ctx.codex_cli._macos_bundle_candidates", return_value=(bundle,)
        ):
            resolved = find_codex_executable(
                environment={"PATH": str(path_executable.parent)}
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.path, path_executable)
        self.assertEqual(resolved.source, "path")

    def test_explicit_override_wins_over_path(self) -> None:
        override = self.executable(self.base / "override" / "codex")
        path_executable = self.executable(self.base / "path-bin" / "codex")

        resolved = find_codex_executable(
            environment={
                "CTX_CODEX": str(override),
                "PATH": str(path_executable.parent),
            }
        )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.path, override)
        self.assertEqual(resolved.source, "environment")

    def test_macos_chatgpt_bundle_is_fallback_after_path(self) -> None:
        bundle = self.executable(
            self.base / "ChatGPT.app" / "Contents" / "Resources" / "codex"
        )
        missing = self.base / "missing" / "codex"

        with (
            mock.patch("ctx.codex_cli.shutil.which", return_value=None) as which,
            mock.patch(
                "ctx.codex_cli._macos_bundle_candidates",
                return_value=(missing, bundle),
            ),
        ):
            search_path = str(self.base / "empty-path")
            resolved = find_codex_executable(environment={"PATH": search_path})

        which.assert_called_once_with("codex", path=search_path)
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.path, bundle)
        self.assertEqual(resolved.source, "chatgpt-app")

    def test_returns_none_when_path_and_bundle_have_no_codex(self) -> None:
        with (
            mock.patch("ctx.codex_cli.shutil.which", return_value=None),
            mock.patch("ctx.codex_cli._macos_bundle_candidates", return_value=()),
        ):
            resolved = find_codex_executable(
                environment={"PATH": str(self.base / "empty-path")}
            )

        self.assertIsNone(resolved)

    def test_missing_override_fails_closed_without_using_path_or_bundle(self) -> None:
        path_executable = self.executable(self.base / "path-bin" / "codex")
        missing = (self.base / "missing" / "codex").resolve()

        with mock.patch(
            "ctx.codex_cli._macos_bundle_candidates",
            return_value=(path_executable,),
        ) as candidates:
            with self.assertRaises(CtxError) as raised:
                find_codex_executable(
                    environment={
                        "CTX_CODEX": str(missing),
                        "PATH": str(path_executable.parent),
                    }
                )

        self.assertEqual(raised.exception.code, "codex.executable-invalid")
        self.assertEqual(raised.exception.exit_code, 4)
        candidates.assert_not_called()

    def test_non_executable_override_fails_closed_without_using_path(self) -> None:
        override = self.base / "override" / "codex"
        override.parent.mkdir()
        override.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        override.chmod(stat.S_IRUSR | stat.S_IWUSR)
        path_executable = self.executable(self.base / "path-bin" / "codex")

        with mock.patch("ctx.codex_cli.shutil.which") as which:
            with self.assertRaises(CtxError) as raised:
                find_codex_executable(
                    environment={
                        "CTX_CODEX": str(override.resolve()),
                        "PATH": str(path_executable.parent),
                    }
                )

        self.assertEqual(raised.exception.code, "codex.executable-invalid")
        self.assertEqual(raised.exception.exit_code, 4)
        which.assert_not_called()

    def test_relative_override_is_invalid_even_when_path_would_resolve_it(self) -> None:
        executable = self.executable(self.base / "path-bin" / "codex")

        with self.assertRaises(CtxError) as raised:
            find_codex_executable(
                environment={
                    "CTX_CODEX": "codex",
                    "PATH": str(executable.parent),
                }
            )

        self.assertEqual(raised.exception.code, "codex.executable-invalid")
        self.assertEqual(raised.exception.exit_code, 4)


if __name__ == "__main__":
    unittest.main()
