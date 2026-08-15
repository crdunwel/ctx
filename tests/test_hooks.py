from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.freshness import seal_freshness
from ctx.services import init_project


class CodexHookLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.ctx_home = self.base / "ctx-home"
        self.project = self.base / "project"
        self.project.mkdir()
        self.source = self.project / "app.py"
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        init_project(self.project, project_id="hook-project", name="Hook Project")
        manifest = self.project / ".ctx" / "context.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "node:\n  id: root\n  name: Hook Project\n",
                "node:\n  id: root\n  name: Hook Project\n"
                "  summary: Initial durable project purpose.\n",
            ),
            encoding="utf-8",
        )
        seal_freshness(self.project)

    def run_ctx(
        self,
        *arguments: str,
        input_text: str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(self.home)
        environment["CTX_HOME"] = str(self.ctx_home)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=cwd or self.project,
            env=environment,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def prompt_payload(self, *, turn: str = "turn-1", prompt: str = "Change the value") -> str:
        return json.dumps(
            {
                "session_id": "session-1",
                "turn_id": turn,
                "cwd": str(self.project),
                "hook_event_name": "UserPromptSubmit",
                "prompt": prompt,
                "model": "test-model",
                "permission_mode": "default",
                "transcript_path": None,
            }
        )

    def stop_payload(self, *, turn: str = "turn-1", active: bool = False) -> str:
        return json.dumps(
            {
                "session_id": "session-1",
                "turn_id": turn,
                "cwd": str(self.project),
                "hook_event_name": "Stop",
                "stop_hook_active": active,
                "last_assistant_message": "Done",
                "model": "test-model",
                "permission_mode": "default",
                "transcript_path": None,
            }
        )

    def begin_from_prompt(self) -> tuple[str, dict[str, object]]:
        result = self.run_ctx("hook", "codex-prompt", input_text=self.prompt_payload())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        context = payload["hookSpecificOutput"]["additionalContext"]
        marker = next(line for line in context.splitlines() if line.startswith("CTX_RECONCILE_RUN="))
        return marker.split("=", 1)[1], payload

    def test_prompt_hydrates_and_source_change_continues_once(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        before_manifest = manifest.read_bytes()
        before_lock = (self.project / ".ctx" / "lock.json").read_bytes()
        run_id, prompt = self.begin_from_prompt()
        context = prompt["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ctx://hook-project", context)
        self.assertIn("immutable pre-edit baseline", context)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual((self.project / ".ctx" / "lock.json").read_bytes(), before_lock)

        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        first = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload())
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        first_payload = json.loads(first.stdout)
        self.assertEqual(first_payload["decision"], "block")
        self.assertIn(f"CTX_RECONCILE_RUN={run_id}", first_payload["reason"])
        self.assertIn("ctx reconcile inspect --run", first_payload["reason"])

        second = self.run_ctx(
            "hook",
            "codex-stop",
            input_text=self.stop_payload(active=True),
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        second_payload = json.loads(second.stdout)
        self.assertNotIn("decision", second_payload)
        self.assertIn("single allowed continuation", second_payload["systemMessage"])

    def test_acknowledge_then_complete_selectively_seals_run(self) -> None:
        run_id, _prompt = self.begin_from_prompt()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")

        inspected = self.run_ctx("reconcile", "inspect", "--run", run_id, "--json")
        self.assertEqual(inspected.returncode, 0, inspected.stdout + inspected.stderr)
        inspection = json.loads(inspected.stdout)
        self.assertEqual(inspection["uncovered"], ["ctx://hook-project"])
        self.assertFalse(inspection["changes"][0]["covered"])

        acknowledged = self.run_ctx(
            "reconcile",
            "acknowledge",
            "ctx://hook-project",
            "--reason",
            "Implementation-only constant change.",
            "--run",
            run_id,
        )
        self.assertEqual(acknowledged.returncode, 0, acknowledged.stdout + acknowledged.stderr)
        completed = self.run_ctx("reconcile", "complete", "--run", run_id)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("1 affected node(s)", completed.stdout)

        stopped = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload(active=True))
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertEqual(json.loads(stopped.stdout), {})
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertTrue(json.loads(status.stdout)["fresh"])

    def test_manifest_update_is_automatically_completed_at_stop(self) -> None:
        _run_id, _prompt = self.begin_from_prompt()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        manifest = self.project / ".ctx" / "context.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "Initial durable project purpose.",
                "Durable project purpose after the implementation change.",
            ),
            encoding="utf-8",
        )

        stopped = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload())
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertEqual(json.loads(stopped.stdout), {})
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_invalid_manifest_gets_one_repair_continuation(self) -> None:
        run_id, _prompt = self.begin_from_prompt()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        manifest = self.project / ".ctx" / "context.yaml"
        manifest.write_text("not: [valid\n", encoding="utf-8")

        first = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload())
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["decision"], "block")
        self.assertIn(f"CTX_RECONCILE_RUN={run_id}", payload["reason"])
        self.assertIn("manifest.invalid", payload["reason"])

        second = self.run_ctx(
            "hook",
            "codex-stop",
            input_text=self.stop_payload(active=True),
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("systemMessage", json.loads(second.stdout))

    def test_stop_continuation_prompt_reuses_original_baseline(self) -> None:
        run_id, _prompt = self.begin_from_prompt()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        first = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload())
        reason = json.loads(first.stdout)["reason"]

        continued = self.run_ctx(
            "hook",
            "codex-prompt",
            input_text=self.prompt_payload(turn="turn-2", prompt=reason),
        )
        self.assertEqual(continued.returncode, 0, continued.stdout + continued.stderr)
        context = json.loads(continued.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn(f"CTX_RECONCILE_RUN={run_id}", context)
        self.assertEqual(len(list((self.ctx_home / "runs").glob("*/*.json"))), 1)

        second = self.run_ctx(
            "hook",
            "codex-stop",
            input_text=self.stop_payload(turn="turn-2", active=True),
        )
        self.assertIn("systemMessage", json.loads(second.stdout))

    def test_completed_run_marker_starts_a_new_run(self) -> None:
        completed_run_id, _prompt = self.begin_from_prompt()
        stopped = self.run_ctx("hook", "codex-stop", input_text=self.stop_payload())
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertEqual(json.loads(stopped.stdout), {})

        submitted = self.run_ctx(
            "hook",
            "codex-prompt",
            input_text=self.prompt_payload(
                turn="turn-2",
                prompt=f"CTX_RECONCILE_RUN={completed_run_id}\nStart an unrelated task",
            ),
        )
        self.assertEqual(submitted.returncode, 0, submitted.stdout + submitted.stderr)
        context = json.loads(submitted.stdout)["hookSpecificOutput"]["additionalContext"]
        marker = next(line for line in context.splitlines() if line.startswith("CTX_RECONCILE_RUN="))
        new_run_id = marker.split("=", 1)[1]

        self.assertNotEqual(new_run_id, completed_run_id)
        self.assertEqual(len(list((self.ctx_home / "runs").glob("*/*.json"))), 2)

    def test_hook_prompt_secret_is_not_persisted_in_run_state(self) -> None:
        secret = "sk-test-secret-prompt-canary"
        prompted = self.run_ctx(
            "hook",
            "codex-prompt",
            input_text=self.prompt_payload(prompt=f"Fix authentication using token={secret}"),
        )
        self.assertEqual(prompted.returncode, 0, prompted.stdout + prompted.stderr)

        run_files = list((self.ctx_home / "runs").glob("*/*.json"))
        self.assertEqual(len(run_files), 1)
        self.assertNotIn(secret.encode("utf-8"), run_files[0].read_bytes())

    def test_missing_lock_can_complete_only_the_reviewed_run_scope(self) -> None:
        (self.project / ".ctx" / "lock.json").unlink()
        run_id, _prompt = self.begin_from_prompt()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")

        acknowledged = self.run_ctx(
            "reconcile",
            "acknowledge",
            "ctx://hook-project",
            "--reason",
            "Implementation-only constant change.",
            "--run",
            run_id,
        )
        self.assertEqual(acknowledged.returncode, 0, acknowledged.stdout + acknowledged.stderr)
        completed = self.run_ctx("reconcile", "complete", "--run", run_id)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertTrue(json.loads(status.stdout)["fresh"])

    def test_user_hook_is_noop_outside_ctx_projects(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        payload = json.loads(self.prompt_payload())
        payload["cwd"] = str(outside)
        prompt = self.run_ctx(
            "hook",
            "codex-prompt",
            input_text=json.dumps(payload),
            cwd=outside,
        )
        self.assertEqual(prompt.returncode, 0, prompt.stdout + prompt.stderr)
        self.assertEqual(json.loads(prompt.stdout), {})
        self.assertFalse(self.ctx_home.exists())

    def test_integrate_codex_cli_is_create_only_and_idempotent(self) -> None:
        first = self.run_ctx(
            "integrate",
            "codex",
            "--hooks",
            "--project",
            str(self.project),
        )
        second = self.run_ctx("integrate", "codex", "--hooks")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("created Codex hooks", first.stdout)
        self.assertIn("unchanged Codex hooks", second.stdout)
        hooks = json.loads((self.project / ".codex" / "hooks.json").read_text())
        self.assertEqual(
            hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
            "ctx hook codex-prompt",
        )
        self.assertEqual(
            hooks["hooks"]["Stop"][0]["hooks"][0]["command"],
            "ctx hook codex-stop",
        )


if __name__ == "__main__":
    unittest.main()
