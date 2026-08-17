from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx import agent_instructions
from ctx.diagnostics import CtxError
from ctx.freshness import seal_freshness
from ctx.runs import begin_run
from ctx.services import init_project


CREATE_CONTENT = """# Repository instructions

Use the checked-in validation command before submitting changes.
"""

UPDATE_CONTENT = """# Repository instructions

Use the repository bootstrap before running the validation command.
"""


class AgentInstructionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.home = self.base / "home"
        self.home.mkdir()
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text(
            "# Example project\n\nRun `python -m unittest`.\n",
            encoding="utf-8",
        )
        (self.project / "app.py").write_text("VALUE = 'before'\n", encoding="utf-8")
        init_project(
            self.project,
            project_id="agents-fixture",
            name="Agents Fixture",
        )
        self._git("init", "-q")
        self._git("config", "user.email", "ctx-tests@example.invalid")
        self._git("config", "user.name", "ctx tests")
        self._commit_all("baseline")
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CTX_HOME": str(self.ctx_home),
                "HOME": str(self.home),
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(self.project),
                *arguments,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def _commit_all(self, message: str) -> None:
        self._git("add", "-A")
        self._git("commit", "--no-verify", "-q", "-m", message)

    def _add_existing_agents(self, content: str = CREATE_CONTENT) -> None:
        (self.project / "AGENTS.md").write_text(content, encoding="utf-8")
        self._commit_all("add instructions")

    def _project_files(self) -> dict[str, str]:
        return {
            path.relative_to(self.project).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(self.project.rglob("*"))
            if path.is_file() and ".git" not in path.relative_to(self.project).parts
        }

    def _payload(
        self,
        disposition: str,
        *,
        content: str = "",
        path: str = "AGENTS.md",
        evidence: tuple[str, ...] = ("app.py",),
    ) -> dict[str, object]:
        return {
            "reviews": [
                {
                    "path": path,
                    "disposition": disposition,
                    "content": content,
                    "evidence": list(evidence),
                    "summary": f"{disposition} is supported by repository evidence.",
                }
            ],
            "summary": f"Reviewed durable instructions and selected {disposition}.",
        }

    def _review_with_payload(
        self,
        payload: dict[str, object],
        **arguments: object,
    ) -> agent_instructions.AgentsReviewResult:
        def fake_runner(
            prepared: object,
            work_directory: Path,
            *,
            progress: object = None,
        ) -> Path:
            del prepared, progress
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            return agent_instructions.review_agent_instructions(
                self.project,
                **arguments,
            )

    def _install_fake_codex(self, payload: dict[str, object]) -> tuple[Path, Path]:
        executable = self.base / "fake-codex"
        record = self.base / "fake-codex-record.json"
        result_source = self.base / "fake-codex-result.json"
        result_source.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        executable.write_text(
            f"""#!{Path(sys.executable).resolve()}
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
prompt = sys.stdin.read()
result_path = Path(arguments[arguments.index("--output-last-message") + 1])
result_path.write_bytes(Path(os.environ["FAKE_AGENTS_RESULT"]).read_bytes())
Path(os.environ["FAKE_AGENTS_RECORD"]).write_text(
    json.dumps({{"argv": arguments, "prompt": prompt}}, sort_keys=True) + "\\n",
    encoding="utf-8",
)
""",
            encoding="utf-8",
        )
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return executable, record

    def _valid_saved_plan_payload(self) -> dict[str, object]:
        reviewed = self._review_with_payload(
            self._payload(
                "create",
                content=CREATE_CONTENT,
                evidence=("README.md",),
            )
        )
        path = self.ctx_home / "agents-plans" / f"{reviewed.plan_id}.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def _write_content_addressed_plan(
        self,
        payload: dict[str, object],
        *,
        hardlink_from: Path | None = None,
    ) -> str:
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        plan_id = hashlib.sha256(canonical).hexdigest()
        directory = self.ctx_home / "agents-plans"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = directory / f"{plan_id}.json"
        if hardlink_from is None:
            target.write_bytes(canonical + b"\n")
        else:
            hardlink_from.write_bytes(canonical + b"\n")
            os.link(hardlink_from, target)
        return plan_id

    def test_codex_receives_exact_generated_prompt_and_guard_flags(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        expected_prompt = agent_instructions.generate_agents_prompt(self.project)
        executable, record_path = self._install_fake_codex(
            self._payload("create", content=CREATE_CONTENT)
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_RECORD": str(record_path),
                "FAKE_AGENTS_RESULT": str(self.base / "fake-codex-result.json"),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(self.project)

        invocation = json.loads(record_path.read_text(encoding="utf-8"))
        arguments = invocation["argv"]
        self.assertEqual(invocation["prompt"], expected_prompt)
        self.assertTrue(expected_prompt.startswith("CTX_AGENTS_REVIEW_PROMPT_VERSION=1\n"))
        self.assertIn(
            "Existing `AGENTS.md` files normally govern future work",
            expected_prompt,
        )
        self.assertIn("No chat transcript, raw task/session notes", expected_prompt)
        self.assertTrue(
            expected_prompt.endswith(
                "Return only the JSON object required by the supplied output schema.\n"
            )
        )
        self.assertEqual(arguments[:2], ["exec", "-C"])
        self.assertIn("--ephemeral", arguments)
        self.assertIn("--ignore-user-config", arguments)
        self.assertIn("--ignore-rules", arguments)
        self.assertIn("--strict-config", arguments)
        self.assertIn('approval_policy="never"', arguments)
        self.assertIn("permissions.ctx-agents.network.enabled=false", arguments)
        self.assertIn('web_search="disabled"', arguments)
        self.assertIn("agents.enabled=false", arguments)
        hooks_index = arguments.index("--disable")
        self.assertEqual(arguments[hooks_index + 1], "hooks")
        self.assertEqual(arguments[-1], "-")
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", arguments)
        self.assertRegex(reviewed.plan_id, r"^[0-9a-f]{64}$")

    def test_cli_review_show_and_apply_exact_plan(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        executable, record_path = self._install_fake_codex(
            self._payload("create", content=CREATE_CONTENT)
        )
        environment = dict(os.environ)
        environment.update(
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_RECORD": str(record_path),
                "FAKE_AGENTS_RESULT": str(self.base / "fake-codex-result.json"),
            }
        )

        reviewed = subprocess.run(
            [sys.executable, "-m", "ctx", "agents", "review", str(self.project)],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(reviewed.returncode, 0, reviewed.stdout + reviewed.stderr)
        match = re.search(r"ctx agents show-plan ([0-9a-f]{64})", reviewed.stdout)
        self.assertIsNotNone(match, reviewed.stdout)
        plan_id = match.group(1)

        shown = subprocess.run(
            [sys.executable, "-m", "ctx", "agents", "show-plan", plan_id],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(shown.returncode, 0, shown.stdout + shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["review"]["content"], CREATE_CONTENT)

        applied = subprocess.run(
            [sys.executable, "-m", "ctx", "agents", "apply", plan_id],
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn("AGENTS UPDATED", applied.stdout)
        self.assertIn("ctx reconcile", applied.stdout)
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )

    def test_missing_root_review_saves_plan_without_project_write_then_applies_idempotently(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        before_review = self._project_files()

        reviewed = self._review_with_payload(
            self._payload("create", content=CREATE_CONTENT)
        )

        self.assertEqual(reviewed.review.disposition, "create")
        self.assertFalse((self.project / "AGENTS.md").exists())
        self.assertEqual(self._project_files(), before_review)
        plan_path = self.ctx_home / "agents-plans" / f"{reviewed.plan_id}.json"
        self.assertTrue(plan_path.is_file())
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertEqual(rendered["review"]["content"], CREATE_CONTENT)
        self.assertFalse(rendered["apply_blocked"])

        first = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(first.action, "created")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )
        second = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )

    def test_existing_agents_is_updated_as_complete_file(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload("update", content=UPDATE_CONTENT)
        )
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )

        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            UPDATE_CONTENT,
        )

    def test_no_op_plan_applies_without_a_file_write(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        target = self.project / "AGENTS.md"
        identity = (target.stat().st_dev, target.stat().st_ino, target.stat().st_mtime_ns)
        reviewed = self._review_with_payload(self._payload("no-op"))

        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(applied.action, "unchanged")
        self.assertIsNone(applied.path)
        self.assertEqual(
            (target.stat().st_dev, target.stat().st_ino, target.stat().st_mtime_ns),
            identity,
        )
        self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)

    def test_clean_existing_target_saves_model_free_no_op(self) -> None:
        self._add_existing_agents()

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            reviewed = agent_instructions.review_agent_instructions(self.project)

        codex.assert_not_called()
        self.assertEqual(reviewed.review.disposition, "no-op")
        self.assertEqual(reviewed.review.evidence, ("AGENTS.md",))
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")

    def test_review_required_plan_is_saved_but_cannot_be_applied(self) -> None:
        reviewed = self._review_with_payload(
            self._payload(
                "review-required",
                evidence=("README.md",),
            )
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertTrue(rendered["apply_blocked"])

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.review-required")
        self.assertFalse((self.project / "AGENTS.md").exists())

    def test_plan_is_stale_when_selected_source_changes_after_review(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'reviewed'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload("create", content=CREATE_CONTENT)
        )
        (self.project / "app.py").write_text("VALUE = 'changed again'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertFalse((self.project / "AGENTS.md").exists())

    def test_unsafe_proposal_path_and_uncopied_evidence_are_rejected(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        proposals = (
            self._payload(
                "create",
                content=CREATE_CONTENT,
                path="../AGENTS.md",
            ),
            self._payload(
                "create",
                content=CREATE_CONTENT,
                evidence=("not-copied.py",),
            ),
        )

        for proposal in proposals:
            with self.subTest(proposal=proposal):
                with self.assertRaises(CtxError) as raised:
                    self._review_with_payload(proposal)
                self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
                self.assertFalse((self.project / "AGENTS.md").exists())
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_staged_review_refuses_unstaged_or_untracked_worktree_state(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'staged'\n", encoding="utf-8")
        self._git("add", "app.py")
        (self.project / "README.md").write_text("unstaged change\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            agent_instructions.generate_agents_prompt(self.project, staged=True)

        self.assertEqual(raised.exception.code, "agents.staged-worktree-dirty")

    def test_staged_plan_applies_and_remains_idempotent_after_target_becomes_unstaged(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'staged'\n", encoding="utf-8")
        self._git("add", "app.py")
        reviewed = self._review_with_payload(
            self._payload("create", content=CREATE_CONTENT),
            staged=True,
        )

        first = agent_instructions.apply_agents_plan(reviewed.plan_id)
        second = agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(first.action, "created")
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )

    def test_created_agents_mode_is_exact_even_under_restrictive_umask(self) -> None:
        reviewed = self._review_with_payload(
            self._payload(
                "create",
                content=CREATE_CONTENT,
                evidence=("README.md",),
            )
        )
        previous = os.umask(0o077)
        try:
            applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        finally:
            os.umask(previous)

        self.assertEqual(applied.action, "created")
        self.assertEqual(
            stat.S_IMODE((self.project / "AGENTS.md").stat().st_mode),
            0o644,
        )

    def test_run_selector_routes_clean_baseline_tracked_edit_as_modified(self) -> None:
        seal_freshness(self.project)
        self._commit_all("fresh lock")
        run = begin_run(self.project, task="change app behavior")
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        prompt = agent_instructions.generate_agents_prompt(
            self.project,
            run_id=run.run_id,
        )

        self.assertIn('"kind": "run"', prompt)
        self.assertIn('"path": "app.py"', prompt)
        self.assertIn('"status": "modified"', prompt)

    def test_non_codex_adapter_is_rejected_before_review(self) -> None:
        with self.assertRaises(CtxError) as raised:
            agent_instructions.review_agent_instructions(
                self.project,
                agent="unconfigured-model",
            )

        self.assertEqual(raised.exception.code, "agents.agent-unsupported")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_missing_root_agents_must_not_be_ignored(self) -> None:
        (self.project / ".gitignore").write_text("AGENTS.md\n", encoding="utf-8")
        self._commit_all("ignore root instructions")

        with self.assertRaises(CtxError) as raised:
            agent_instructions.generate_agents_prompt(self.project)

        self.assertEqual(raised.exception.code, "agents.target-ineligible")
        self.assertFalse((self.project / "AGENTS.md").exists())

    def test_content_addressed_plan_rejects_non_string_selector_kind(self) -> None:
        payload = self._valid_saved_plan_payload()
        selector = payload["selector"]
        self.assertIsInstance(selector, dict)
        selector["kind"] = []
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_content_addressed_plan_rejects_non_string_target_state(self) -> None:
        payload = self._valid_saved_plan_payload()
        target = payload["target"]
        self.assertIsInstance(target, dict)
        target["state"] = []
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_content_addressed_plan_rejects_unicode_format_control_in_content(self) -> None:
        payload = self._valid_saved_plan_payload()
        review = payload["review"]
        self.assertIsInstance(review, dict)
        review["content"] = "# Repository instructions\n\n\u202econcealed direction\n"
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_content_addressed_plan_rejects_casefolded_protected_target(self) -> None:
        payload = self._valid_saved_plan_payload()
        target = payload["target"]
        review = payload["review"]
        self.assertIsInstance(target, dict)
        self.assertIsInstance(review, dict)
        target.update(
            {
                "path": ".Git/AGENTS.md",
                "state": "existing",
                "scope": ".Git",
                "baseline": {
                    "device": 1,
                    "inode": 1,
                    "size": len(CREATE_CONTENT.encode("utf-8")),
                    "modified_ns": 1,
                    "mode": 0o644,
                    "digest": "sha256:" + hashlib.sha256(
                        CREATE_CONTENT.encode("utf-8")
                    ).hexdigest(),
                },
            }
        )
        review.update(
            {
                "path": ".Git/AGENTS.md",
                "disposition": "no-op",
                "content": "",
            }
        )
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_hardlinked_saved_plan_is_rejected(self) -> None:
        payload = self._valid_saved_plan_payload()
        payload["summary"] = "A valid proposal stored through an unsafe hardlink."
        outside = self.base / "outside-plan.json"
        plan_id = self._write_content_addressed_plan(
            payload,
            hardlink_from=outside,
        )

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")
        self.assertEqual(outside.stat().st_nlink, 2)

    def test_hardlinked_agents_target_is_rejected(self) -> None:
        outside = self.base / "outside-agents.md"
        outside.write_text(CREATE_CONTENT, encoding="utf-8")
        os.link(outside, self.project / "AGENTS.md")

        with self.assertRaises(CtxError) as raised:
            agent_instructions.generate_agents_prompt(self.project)

        self.assertEqual(raised.exception.code, "agents.target-unsafe")
        self.assertEqual(outside.stat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
