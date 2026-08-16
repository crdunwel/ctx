from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx.demo import _publish_demo, create_demo
from ctx.diagnostics import CtxError


REPOSITORY = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)


class DemoCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.environment = os.environ.copy()
        self.environment["PYTHONPATH"] = str(REPOSITORY / "src")
        self.environment["CTX_HOME"] = str(self.ctx_home)
        # The demo is entirely bundled and must never attempt to start Codex.
        self.environment["CTX_CODEX"] = str(self.base / "must-not-run-codex")

    def run_ctx(
        self,
        *arguments: str,
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(PYTHON), "-m", "ctx", *arguments],
            cwd=cwd or self.base,
            env=self.environment,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def test_demo_is_immediately_hydratable_and_fresh(self) -> None:
        created = self.run_ctx("demo")
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.assertEqual(created.stderr, "")
        root = self.base.resolve() / "ctx-permit-board-demo"
        self.assertIn(f"DEMO READY {root}", created.stdout)
        self.assertIn("Ask Codex:", created.stdout)
        self.assertIn("Codex CLI/TUI: run /hooks", created.stdout)
        self.assertIn("Codex desktop: /hooks is not available", created.stdout)
        self.assertIn("ctx hydrate --from . --task", created.stdout)
        self.assertTrue((root / ".ctx" / "context.yaml").is_file())
        self.assertTrue((root / ".ctx" / "lock.json").is_file())
        self.assertTrue((root / ".codex" / "hooks.json").is_file())
        self.assertTrue(
            (root / "permit_board" / "policy" / ".ctx" / "context.yaml").is_file()
        )
        self.assertFalse(self.ctx_home.exists())

        validation = self.run_ctx("validate", str(root), "--strict")
        status = self.run_ctx("status", str(root), "--check")
        sample_tests = subprocess.run(
            [str(PYTHON), "-m", "unittest", "discover", "-s", "tests", "-q"],
            cwd=root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertEqual(sample_tests.returncode, 0, sample_tests.stdout + sample_tests.stderr)

        root_hydration = self.run_ctx("hydrate", "--from", str(root), "--json")
        self.assertEqual(
            root_hydration.returncode,
            0,
            root_hydration.stdout + root_hydration.stderr,
        )
        root_payload = json.loads(root_hydration.stdout)
        self.assertEqual(
            [node["uri"] for node in root_payload["nodes"]],
            ["ctx://permit-board-demo"],
        )
        self.assertEqual(
            [scope["uri"] for scope in root_payload["dormant_scopes"]],
            ["ctx://permit-board-demo/policy"],
        )

        hydration = self.run_ctx(
            "hydrate",
            "--from",
            str(root / "permit_board" / "policy" / "eligibility.py"),
            "--task",
            "Explain payment precedence",
            "--json",
        )
        self.assertEqual(hydration.returncode, 0, hydration.stdout + hydration.stderr)
        payload = json.loads(hydration.stdout)
        self.assertEqual(payload["active_scope"]["uri"], "ctx://permit-board-demo/policy")
        self.assertEqual(
            [node["uri"] for node in payload["nodes"]],
            ["ctx://permit-board-demo", "ctx://permit-board-demo/policy"],
        )
        self.assertTrue(payload["freshness"]["project_fresh"])

        fees = root / "permit_board" / "policy" / "fees.py"
        fees.write_text(fees.read_text(encoding="utf-8") + "\n# policy changed\n", encoding="utf-8")
        changed_status = self.run_ctx("status", str(root), "--json")
        self.assertEqual(
            changed_status.returncode,
            0,
            changed_status.stdout + changed_status.stderr,
        )
        states = {
            node["uri"]: node["state"]
            for node in json.loads(changed_status.stdout)["nodes"]
        }
        self.assertEqual(states["ctx://permit-board-demo"], "fresh")
        self.assertEqual(states["ctx://permit-board-demo/policy"], "stale")

    def test_demo_codex_prompt_hook_hydrates_without_registry_state(self) -> None:
        root = self.base.resolve() / "sample"
        created = self.run_ctx("demo", str(root))
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)

        hook = self.run_ctx(
            "hook",
            "codex-prompt",
            cwd=root,
            input_text=json.dumps(
                {
                    "session_id": "demo-session",
                    "turn_id": "demo-turn",
                    "cwd": str(root / "permit_board" / "policy"),
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": "Explain payment precedence",
                    "model": "test-model",
                    "permission_mode": "default",
                    "transcript_path": None,
                }
            ),
        )
        self.assertEqual(hook.returncode, 0, hook.stdout + hook.stderr)
        payload = json.loads(hook.stdout)
        context = payload["hookSpecificOutput"]["additionalContext"]
        self.assertIn("CTX_RECONCILE_RUN=", context)
        self.assertIn("ctx://permit-board-demo/policy", context)
        self.assertIn("Required payment precedes readiness", context)
        self.assertFalse((self.ctx_home / "registry.json").exists())

        fees = root / "permit_board" / "policy" / "fees.py"
        fees.write_text(fees.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
        stopped = self.run_ctx(
            "hook",
            "codex-stop",
            cwd=root,
            input_text=json.dumps(
                {
                    "session_id": "demo-session",
                    "turn_id": "demo-turn",
                    "cwd": str(root / "permit_board" / "policy"),
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                    "last_assistant_message": "Done",
                    "model": "test-model",
                    "permission_mode": "default",
                    "transcript_path": None,
                }
            ),
        )
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        stop_payload = json.loads(stopped.stdout)
        self.assertEqual(stop_payload["decision"], "block")
        self.assertIn("CTX_RECONCILE_RUN=", stop_payload["reason"])
        self.assertIn("ctx://permit-board-demo/policy", stop_payload["reason"])

    def test_demo_never_overwrites_an_existing_target(self) -> None:
        target = self.base / "occupied"
        target.mkdir()
        canary = target / "keep.txt"
        canary.write_text("keep\n", encoding="utf-8")

        result = self.run_ctx("demo", str(target))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("demo.target-exists", result.stderr)
        self.assertEqual(canary.read_text(encoding="utf-8"), "keep\n")
        self.assertEqual(sorted(path.name for path in target.iterdir()), ["keep.txt"])

    def test_demo_does_not_replace_a_target_that_appears_during_publish(self) -> None:
        source = self.base / "prepared"
        source.mkdir()
        (source / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
        target = self.base / "raced"
        original_mkdir = os.mkdir
        raced = False

        def create_target_first(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal raced
            if path == target.name and dir_fd is not None and not raced:
                raced = True
                original_mkdir(target)
            original_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch("ctx.demo.os.mkdir", side_effect=create_target_first):
            with self.assertRaises(CtxError) as raised:
                _publish_demo(source, target)

        self.assertEqual(raised.exception.code, "demo.target-exists")
        self.assertTrue(target.is_dir())
        self.assertEqual(list(target.iterdir()), [])

    def test_prepared_tree_swap_cannot_change_published_demo(self) -> None:
        target = self.base / "anchored-demo"
        original_publish = _publish_demo

        def swap_path_before_publish(
            source: Path,
            destination: Path,
            **kwargs: object,
        ) -> None:
            anchored = source.with_name("anchored-original")
            os.rename(source, anchored)
            source.mkdir()
            (source / "README.md").write_text("replacement\n", encoding="utf-8")
            original_publish(source, destination, **kwargs)

        with mock.patch(
            "ctx.demo._publish_demo",
            side_effect=swap_path_before_publish,
        ):
            create_demo(target)

        self.assertTrue((target / ".ctx" / "context.yaml").is_file())
        self.assertTrue((target / ".ctx" / "lock.json").is_file())
        self.assertNotEqual(
            (target / "README.md").read_text(encoding="utf-8"),
            "replacement\n",
        )

    def test_interrupt_during_publish_rolls_back_partial_target(self) -> None:
        source = self.base / "interrupt-source"
        source.mkdir()
        for index in range(3):
            (source / f"file-{index}.txt").write_text(str(index), encoding="utf-8")
        target = self.base / "interrupt-target"
        original_link = os.link
        calls = 0

        def interrupt_link(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            original_link(*args, **kwargs)

        with mock.patch("ctx.demo.os.link", side_effect=interrupt_link):
            with self.assertRaises(KeyboardInterrupt):
                _publish_demo(source, target)

        self.assertFalse(target.exists())

    def test_demo_rejects_symlinked_targets_and_parents(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        target_link = self.base / "linked-target"
        target_link.symlink_to(outside, target_is_directory=True)

        direct = self.run_ctx("demo", str(target_link))
        self.assertEqual(direct.returncode, 3, direct.stdout + direct.stderr)
        self.assertIn("demo.target-symlink", direct.stderr)

        parent_link = self.base / "linked-parent"
        parent_link.symlink_to(outside, target_is_directory=True)
        nested = self.run_ctx("demo", str(parent_link / "sample"))
        self.assertEqual(nested.returncode, 3, nested.stdout + nested.stderr)
        self.assertIn("demo.parent-symlink", nested.stderr)
        self.assertFalse((outside / "sample").exists())

    def test_demo_refuses_a_nested_project(self) -> None:
        parent = self.base / "project"
        parent.mkdir()
        initialized = self.run_ctx("init", str(parent), "--id", "outer", "--name", "Outer")
        self.assertEqual(initialized.returncode, 0, initialized.stdout + initialized.stderr)

        result = self.run_ctx("demo", str(parent / "nested"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("demo.inside-project", result.stderr)
        self.assertFalse((parent / "nested").exists())


if __name__ == "__main__":
    unittest.main()
