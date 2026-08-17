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


def _assessment(
    path: str,
    status: str,
    *,
    evidence: tuple[str, ...] | None = None,
) -> dict[str, object]:
    return {
        "path": path,
        "status": status,
        "evidence": list(evidence if evidence is not None else (path,)),
        "summary": f"{path} is dispositioned as {status}.",
    }


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

    def _prepare_truncated_non_target_review(self) -> Path:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text(
            "".join(
                f"CORRECTION_{index:05d} = 'bounded evidence line'\n"
                for index in range(4_000)
            ),
            encoding="utf-8",
        )
        self._commit_all("large source change for correction review")
        return source

    def _exact_update_edits(self, materialized: str) -> tuple[dict[str, str], ...]:
        baseline = (self.project / "AGENTS.md").read_text(encoding="utf-8")
        if materialized == baseline:
            return ({"old": baseline, "new": materialized},)
        prefix = 0
        limit = min(len(baseline), len(materialized))
        while prefix < limit and baseline[prefix] == materialized[prefix]:
            prefix += 1
        suffix = 0
        suffix_limit = min(len(baseline) - prefix, len(materialized) - prefix)
        while (
            suffix < suffix_limit
            and baseline[len(baseline) - suffix - 1]
            == materialized[len(materialized) - suffix - 1]
        ):
            suffix += 1
        old_end = len(baseline) - suffix
        new_end = len(materialized) - suffix
        if prefix:
            prefix = baseline.rfind("\n", 0, prefix) + 1
        if old_end < len(baseline):
            following_newline = baseline.find("\n", old_end)
            if following_newline >= 0:
                extension = following_newline + 1 - old_end
                old_end += extension
                new_end += extension
        if prefix == old_end:
            if prefix:
                prefix -= 1
            elif old_end < len(baseline):
                old_end += 1
                new_end += 1
        return (
            {
                "old": baseline[prefix:old_end],
                "new": materialized[prefix:new_end],
            },
        )

    def _payload(
        self,
        disposition: str,
        *,
        content: str = "",
        path: str = "AGENTS.md",
        evidence: tuple[str, ...] = ("app.py",),
        edits: tuple[dict[str, str], ...] = (),
        raw_update_content: bool = False,
        assessments: tuple[dict[str, object], ...] | None = None,
    ) -> dict[str, object]:
        if disposition == "update" and content and not edits and not raw_update_content:
            edits = self._exact_update_edits(content)
            content = ""
        if assessments is None:
            if "app.py" not in evidence:
                assessments = ()
            elif disposition in {"create", "update"}:
                assessments = (_assessment("app.py", "requires-update"),)
            elif disposition == "no-op":
                assessments = (_assessment("app.py", "implementation-only"),)
            else:
                assessments = (_assessment("app.py", "insufficient-evidence"),)
        return {
            "reviews": [
                {
                    "path": path,
                    "disposition": disposition,
                    "content": content,
                    "edits": list(edits),
                    "evidence": list(evidence),
                    "assessments": list(assessments),
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
            prompt_suffix: str = "",
        ) -> Path:
            del prepared, progress, prompt_suffix
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

    def _install_sequenced_fake_codex(
        self,
        payloads: tuple[dict[str, object], ...],
    ) -> tuple[Path, Path, Path, Path]:
        executable = self.base / "fake-codex-sequence"
        record = self.base / "fake-codex-sequence-record.jsonl"
        result_source = self.base / "fake-codex-sequence-results.json"
        counter = self.base / "fake-codex-sequence-counter"
        result_source.write_text(
            json.dumps(payloads, ensure_ascii=True, sort_keys=True) + "\n",
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
counter_path = Path(os.environ["FAKE_AGENTS_SEQUENCE_COUNTER"])
index = int(counter_path.read_text(encoding="utf-8")) if counter_path.exists() else 0
payloads = json.loads(Path(os.environ["FAKE_AGENTS_SEQUENCE_RESULTS"]).read_text(encoding="utf-8"))
result_path = Path(arguments[arguments.index("--output-last-message") + 1])
result_path.write_text(
    json.dumps(payloads[index], ensure_ascii=True, sort_keys=True) + "\\n",
    encoding="utf-8",
)
with Path(os.environ["FAKE_AGENTS_SEQUENCE_RECORD"]).open("a", encoding="utf-8") as stream:
    stream.write(
        json.dumps(
            {{"argv": arguments, "cwd": os.getcwd(), "prompt": prompt, "result": str(result_path)}},
            sort_keys=True,
        )
        + "\\n"
    )
counter_path.write_text(str(index + 1), encoding="utf-8")
if index == int(os.environ.get("FAKE_AGENTS_RACE_ATTEMPT", "-1")):
    Path(os.environ["FAKE_AGENTS_RACE_PATH"]).write_text(
        os.environ["FAKE_AGENTS_RACE_CONTENT"],
        encoding="utf-8",
    )
""",
            encoding="utf-8",
        )
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return executable, record, result_source, counter

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
        self.assertTrue(expected_prompt.startswith("CTX_AGENTS_REVIEW_PROMPT_VERSION=4\n"))
        self.assertIn(
            "Existing `AGENTS.md` files normally govern future work",
            expected_prompt,
        )
        self.assertIn(
            "Do not choose `insufficient-evidence` solely because",
            expected_prompt,
        )
        self.assertIn(
            "compare the complete current selected files",
            expected_prompt,
        )
        self.assertIn('For `update`, return `content: ""`', expected_prompt)
        self.assertIn("smallest uniquely identifying anchors", expected_prompt)
        self.assertIn(
            "current target itself establishes which subject-matter",
            expected_prompt,
        )
        self.assertIn(
            "Choosing concise normative wording is the",
            expected_prompt,
        )
        self.assertIn(
            "reviewer's task, not a missing-evidence condition",
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

    def test_prompt_and_provider_schema_define_exact_edit_transport(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        prompt = agent_instructions.generate_agents_prompt(self.project)

        self.assertTrue(prompt.startswith("CTX_AGENTS_REVIEW_PROMPT_VERSION=4\n"))
        self.assertIn("The `edits` field is always present", prompt)
        self.assertIn('For `update`, return `content: ""`', prompt)
        self.assertIn("Full replacement content is", prompt)
        self.assertIn("occur exactly once in the inspected target", prompt)
        self.assertIn(
            str(agent_instructions.MAX_AGENTS_EXACT_EDIT_BYTES),
            prompt,
        )
        self.assertIn(
            str(agent_instructions.AGENTS_EXACT_EDIT_OLD_BYTE_FLOOR),
            prompt,
        )
        self.assertIn("smallest uniquely identifying anchors", prompt)
        review_schema = agent_instructions._OUTPUT_SCHEMA["properties"]["reviews"][
            "items"
        ]
        self.assertIn("edits", review_schema["required"])
        edits_schema = review_schema["properties"]["edits"]
        self.assertEqual(
            edits_schema["maxItems"],
            agent_instructions.MAX_AGENTS_EXACT_EDITS,
        )
        self.assertEqual(
            edits_schema["items"],
            {
                "type": "object",
                "properties": {
                    "old": {"type": "string"},
                    "new": {"type": "string"},
                },
                "required": ["old", "new"],
                "additionalProperties": False,
            },
        )

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

    def test_existing_agents_wholesale_replacement_is_rejected(self) -> None:
        baseline = "# Repository instructions\n" + "".join(
            f"Rule {index:03d}: preserve this established instruction.\n"
            for index in range(100)
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        replacement = "# Repository instructions\n\nUse the new workflow.\n"

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload("update", content=replacement)
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("replaces too much existing guidance", str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_existing_agents_localized_update_passes_preservation_guard(self) -> None:
        baseline = "# Repository instructions\n" + "".join(
            f"Rule {index:03d}: preserve this established instruction.\n"
            for index in range(100)
        )
        proposed = baseline.replace(
            "Rule 050: preserve this established instruction.\n",
            "Rule 050: run the repository bootstrap before validation.\n",
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload("update", content=proposed)
        )
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            proposed,
        )

    def test_exact_edit_materializes_and_saves_full_large_agents_content(self) -> None:
        baseline = "# Repository instructions\n\n" + "".join(
            f"Rule {index:04d}: preserve this established instruction and its scope.\n"
            for index in range(3_500)
        )
        old = "Rule 1750: preserve this established instruction and its scope.\n"
        new = "Rule 1750: run the repository bootstrap before validation.\n"
        materialized = baseline.replace(old, new)
        encoded = baseline.encode("utf-8")
        self.assertGreater(
            len(encoded),
            agent_instructions.MAX_AGENTS_EXACT_EDIT_BYTES,
        )
        self.assertLess(len(encoded), agent_instructions.MAX_AGENTS_FILE_BYTES)
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "update",
                edits=({"old": old, "new": new},),
            )
        )

        self.assertEqual(reviewed.review.content, materialized)
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertEqual(rendered["review"]["content"], materialized)
        self.assertNotIn("edits", rendered["review"])
        saved = json.loads(
            (
                self.ctx_home
                / "agents-plans"
                / f"{reviewed.plan_id}.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(saved["review"]["content"], materialized)
        self.assertNotIn("edits", saved["review"])
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            materialized,
        )

    def test_exact_edit_rejects_whole_large_target_anchor_but_accepts_local_span(
        self,
    ) -> None:
        baseline = "# Repository instructions\n\n" + "".join(
            f"Rule {index:03d}: preserve this established instruction.\n"
            for index in range(300)
        )
        old = "Rule 150: preserve this established instruction.\n"
        new = "Rule 150: run the repository bootstrap before validation.\n"
        materialized = baseline.replace(old, new)
        self.assertGreater(
            len(baseline.encode("utf-8")),
            agent_instructions.AGENTS_EXACT_EDIT_OLD_BYTE_FLOOR,
        )
        self.assertLess(
            len(baseline.encode("utf-8")) + len(materialized.encode("utf-8")),
            agent_instructions.MAX_AGENTS_EXACT_EDIT_BYTES,
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    edits=({"old": baseline, "new": materialized},),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("match too much unchanged baseline text", str(raised.exception))
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                edits=({"old": old, "new": new},),
            )
        )
        self.assertEqual(reviewed.review.content, materialized)
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            materialized,
        )

    def test_exact_edit_rejects_ambiguous_or_missing_old_span(self) -> None:
        baseline = (
            "# Repository instructions\n\n"
            "Shared validation guidance.\n"
            "Keep the release process stable.\n"
            "Shared validation guidance.\n"
            "Overlapping occurrence token: aaaa.\n"
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        for old, expected_detail in (
            ("Shared validation guidance.\n", "ambiguous"),
            ("aaa", "ambiguous"),
            ("Guidance that does not exist.\n", "does not match"),
        ):
            with self.subTest(old=old):
                with self.assertRaises(CtxError) as raised:
                    self._review_with_payload(
                        self._payload(
                            "update",
                            edits=(
                                {
                                    "old": old,
                                    "new": "Run the repository validation command.\n",
                                },
                            ),
                        )
                    )

                self.assertEqual(
                    raised.exception.code,
                    "agents.agent-output-invalid",
                )
                self.assertIn(expected_detail, str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_exact_edit_rejects_overlapping_old_spans(self) -> None:
        baseline = (
            "# Repository instructions\n\n"
            "Use the alpha beta gamma workflow before validation.\n"
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    edits=(
                        {"old": "alpha beta", "new": "alpha bootstrap"},
                        {"old": "beta gamma", "new": "validation gamma"},
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("overlap", str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_exact_edits_splice_out_of_order_against_original_baseline(self) -> None:
        alpha = "Alpha anchor rule remains unchanged.\n"
        beta = "Beta anchor rule remains unchanged.\n"
        alpha_new = "Alpha now references the Beta anchor rule remains unchanged.\n"
        beta_new = "Beta now requires repository validation.\n"
        header = "# Repository instructions\n\n"
        filler = "".join(f"Filler rule {index:02d}.\n" for index in range(12))
        baseline = header + alpha + filler + beta
        materialized = header + alpha_new + filler + beta_new
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "update",
                edits=(
                    {"old": beta, "new": beta_new},
                    {"old": alpha, "new": alpha_new},
                ),
            )
        )

        self.assertEqual(reviewed.review.content, materialized)
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            materialized,
        )

    def test_exact_edits_can_remove_unsafe_text_from_inspected_baseline(self) -> None:
        unsafe_lines = (
            "Remove carriage\rreturn text.\n",
            "Remove nul\x00text.\n",
            "Remove format\u202etext.\n",
            "Remove .ctx-agents-change.patch marker.\n",
        )
        replacements = (
            "Use LF-only instruction text.\n",
            "Keep instruction text free of nul bytes.\n",
            "Keep instruction text directionally explicit.\n",
            "Do not reference generated adapter paths.\n",
        )
        baseline = (
            "# Repository instructions\n\n"
            + "".join(unsafe_lines)
            + "".join(f"Stable filler rule {index:02d}.\n" for index in range(20))
        )
        materialized = baseline
        for old, new in zip(unsafe_lines, replacements, strict=True):
            materialized = materialized.replace(old, new)
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "update",
                edits=tuple(
                    {"old": old, "new": new}
                    for old, new in zip(unsafe_lines, replacements, strict=True)
                ),
            )
        )

        self.assertEqual(reviewed.review.content, materialized)
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_bytes(),
            materialized.encode("utf-8"),
        )

    def test_exact_edits_reject_identity_and_net_identity_updates(self) -> None:
        baseline = (
            "# Repository instructions\n\n"
            "Boundary: LEFT-MIDDLE-RIGHT.\n"
            "Run validation before submitting.\n"
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        cases = (
            (
                {"old": "Run validation", "new": "Run validation"},
            ),
            (
                {"old": "LEFT-", "new": "LEFT-MIDDLE-"},
                {"old": "MIDDLE-RIGHT", "new": "RIGHT"},
            ),
        )

        for edits in cases:
            with self.subTest(edits=edits):
                with self.assertRaises(CtxError) as raised:
                    self._review_with_payload(
                        self._payload("update", edits=edits)
                    )
                self.assertEqual(
                    raised.exception.code,
                    "agents.agent-output-invalid",
                )
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_empty_agents_target_requires_one_empty_old_edit(self) -> None:
        self._add_existing_agents("")
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    edits=(
                        {"old": "", "new": "# Repository instructions\n"},
                        {"old": "", "new": "\nRun validation.\n"},
                    ),
                )
            )
        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")

        reviewed = self._review_with_payload(
            self._payload(
                "update",
                edits=({"old": "", "new": CREATE_CONTENT},),
            )
        )
        self.assertEqual(reviewed.review.content, CREATE_CONTENT)
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )

    def test_update_rejects_combined_full_content_and_exact_edits(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    content=UPDATE_CONTENT,
                    edits=(
                        {
                            "old": "checked-in validation command",
                            "new": "repository bootstrap and validation commands",
                        },
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("empty content", str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_update_rejects_full_content_without_exact_edits(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    content=UPDATE_CONTENT,
                    raw_update_content=True,
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("empty content", str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_non_update_dispositions_reject_exact_edits(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'create'\n", encoding="utf-8")
        edit = {
            "old": "checked-in validation command",
            "new": "repository bootstrap and validation commands",
        }
        with self.assertRaises(CtxError) as create_raised:
            self._review_with_payload(
                self._payload(
                    "create",
                    content=CREATE_CONTENT,
                    edits=(edit,),
                )
            )
        self.assertEqual(
            create_raised.exception.code,
            "agents.agent-output-invalid",
        )

        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'existing'\n", encoding="utf-8")
        for disposition, status in (
            ("no-op", "implementation-only"),
            ("review-required", "insufficient-evidence"),
        ):
            with self.subTest(disposition=disposition):
                with self.assertRaises(CtxError) as raised:
                    self._review_with_payload(
                        self._payload(
                            disposition,
                            edits=(edit,),
                            assessments=(
                                _assessment("app.py", status),
                            ),
                        )
                    )
                self.assertEqual(
                    raised.exception.code,
                    "agents.agent-output-invalid",
                )
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_exact_edit_transport_enforces_count_byte_and_text_bounds(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        safe_old = "checked-in validation command"
        cases: tuple[tuple[str, tuple[dict[str, str], ...]], ...] = (
            (
                "count",
                tuple(
                    {"old": f"missing old span {index}", "new": "replacement"}
                    for index in range(agent_instructions.MAX_AGENTS_EXACT_EDITS + 1)
                ),
            ),
            (
                "bytes",
                (
                    {
                        "old": "x" * 32_769,
                        "new": "y" * 32_768,
                    },
                ),
            ),
            (
                "control",
                ({"old": safe_old, "new": "unsafe\x00replacement"},),
            ),
            (
                "empty-old-nonempty-target",
                ({"old": "", "new": "replacement"},),
            ),
            (
                "surrogate-old",
                ({"old": "\ud800", "new": "replacement"},),
            ),
            (
                "surrogate-new",
                ({"old": safe_old, "new": "\ud800"},),
            ),
            (
                "unicode-bytes",
                ({"old": safe_old, "new": "λ" * 32_760},),
            ),
            (
                "generated-path",
                (
                    {
                        "old": safe_old,
                        "new": "Read .ctx-agents-change.patch before editing.",
                    },
                ),
            ),
        )

        for case, edits in cases:
            with self.subTest(case=case):
                with self.assertRaises(CtxError) as raised:
                    self._review_with_payload(
                        self._payload("update", edits=edits)
                    )
                self.assertEqual(
                    raised.exception.code,
                    "agents.agent-output-invalid",
                )
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            CREATE_CONTENT,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_exact_edit_rejects_derived_target_over_size_limit(self) -> None:
        header = "# Repository instructions\n\n"
        anchor = "Unique size anchor.\n"
        target_size = agent_instructions.MAX_AGENTS_FILE_BYTES - 1_024
        padding_size = target_size - len(header.encode("utf-8")) - len(
            anchor.encode("utf-8")
        ) - 1
        baseline = header + ("x" * padding_size) + "\n" + anchor
        self.assertEqual(len(baseline.encode("utf-8")), target_size)
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    edits=(
                        {
                            "old": anchor,
                            "new": anchor.rstrip("\n") + ("y" * 2_048) + "\n",
                        },
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertIn("oversized target", str(raised.exception))
        self.assertEqual(
            (self.project / "AGENTS.md").read_bytes(),
            baseline.encode("utf-8"),
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_exact_edit_target_race_is_rejected_before_plan_save(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        target = self.project / "AGENTS.md"
        payload = self._payload(
            "update",
            edits=(
                {
                    "old": "checked-in validation command",
                    "new": "repository bootstrap and validation commands",
                },
            ),
        )

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del prepared, progress, prompt_suffix
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            target.write_text(
                UPDATE_CONTENT + "\nConcurrent target change.\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(self.project)

        self.assertEqual(raised.exception.code, "agents.target-changed")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_apply_rejects_forged_wholesale_update_plan(self) -> None:
        baseline = "# Repository instructions\n" + "".join(
            f"Rule {index:03d}: preserve this established instruction.\n"
            for index in range(100)
        )
        localized = baseline.replace(
            "Rule 050: preserve this established instruction.\n",
            "Rule 050: run the repository bootstrap before validation.\n",
        )
        self._add_existing_agents(baseline)
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload("update", content=localized)
        )
        saved_path = self.ctx_home / "agents-plans" / f"{reviewed.plan_id}.json"
        payload = json.loads(saved_path.read_text(encoding="utf-8"))
        review = payload["review"]
        self.assertIsInstance(review, dict)
        review["content"] = "# Repository instructions\n\nUse the new workflow.\n"
        forged_plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(forged_plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            baseline,
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

    def test_no_op_apply_rejects_target_race_before_early_return(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(self._payload("no-op"))
        target = self.project / "AGENTS.md"
        original_matches = agent_instructions._matches_target_baseline
        raced = False

        def race_after_initial_match(
            current: tuple[bytes, os.stat_result] | None,
            baseline: agent_instructions.AgentsTarget,
        ) -> bool:
            nonlocal raced
            matched = original_matches(current, baseline)
            if not raced:
                raced = True
                target.write_text(UPDATE_CONTENT, encoding="utf-8")
            return matched

        with mock.patch.object(
            agent_instructions,
            "_matches_target_baseline",
            side_effect=race_after_initial_match,
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertTrue(raced)
        self.assertIn(
            raised.exception.code,
            {"agents.plan-stale", "agents.project-changed"},
        )
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)

    def test_no_op_apply_rejects_inventory_that_becomes_incomplete(self) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(self._payload("no-op"))
        target = self.project / "AGENTS.md"
        target_identity = (
            target.stat().st_dev,
            target.stat().st_ino,
            target.stat().st_mtime_ns,
        )
        inventory_checks = 0

        def incomplete_after_precheck(inventory: object) -> tuple[str, ...]:
            nonlocal inventory_checks
            del inventory
            inventory_checks += 1
            return () if inventory_checks == 1 else ("forced incomplete inventory",)

        with mock.patch.object(
            agent_instructions,
            "inventory_evidence_reasons",
            side_effect=incomplete_after_precheck,
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(inventory_checks, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)
        self.assertEqual(
            (
                target.stat().st_dev,
                target.stat().st_ino,
                target.stat().st_mtime_ns,
            ),
            target_identity,
        )
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'after'\n")

    def test_clean_existing_target_saves_model_free_no_op(self) -> None:
        self._add_existing_agents()

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            reviewed = agent_instructions.review_agent_instructions(self.project)

        codex.assert_not_called()
        self.assertEqual(reviewed.review.disposition, "no-op")
        self.assertEqual(reviewed.review.evidence, ("AGENTS.md",))
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")

    def test_large_normal_index_flag_inventory_does_not_fail_review(self) -> None:
        self._add_existing_agents()
        padding = "x" * 80
        for index in range(1_400):
            (self.project / f"tracked-{index:04d}-{padding}.txt").write_text(
                "",
                encoding="utf-8",
            )
        hidden = self.project / f"z-hidden-{padding}.txt"
        hidden.write_text("", encoding="utf-8")
        self._commit_all("add large normal tracked inventory")
        flags = self._git("ls-files", "-v", "-z").stdout
        self.assertGreater(len(flags.encode("utf-8")), 127 * 1_024)
        self.assertGreater(flags.index(hidden.name), 127 * 1_024)
        self.assertTrue(
            all(
                record.startswith("H ")
                for record in flags.split("\0")
                if record
            )
        )

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            reviewed = agent_instructions.review_agent_instructions(self.project)

        codex.assert_not_called()
        self.assertEqual(reviewed.review.disposition, "no-op")

        self._git("update-index", "--skip-worktree", hidden.name)
        with self.assertRaises(CtxError) as raised:
            agent_instructions.review_agent_instructions(self.project)
        self.assertEqual(raised.exception.code, "agents.git-index-flags")

    def test_since_target_only_commit_invokes_model_and_exposes_target_change(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        self._commit_all("update instructions")
        resolved_base = self._git("rev-parse", "HEAD^").stdout.strip()
        payload = self._payload(
            "no-op",
            evidence=("AGENTS.md",),
            assessments=(
                _assessment("AGENTS.md", "already-covered"),
            ),
        )
        captured: dict[str, object] = {}

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del progress, prompt_suffix
            captured["selector"] = prepared.selector
            captured["prompt"] = agent_instructions.render_agents_review_prompt(prepared)
            captured["changes"] = (
                prepared.snapshot_root / agent_instructions.AGENTS_CHANGE_PATH
            ).read_bytes()
            captured["target_change"] = (
                prepared.snapshot_root
                / agent_instructions.AGENTS_TARGET_CHANGE_PATH
            ).read_bytes()
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )

        selector = captured["selector"]
        self.assertIsInstance(selector, agent_instructions.AgentsSelector)
        self.assertEqual(selector.changed_paths, ())
        prompt = str(captured["prompt"])
        selected_change_scope = prompt.partition('"selected_changes":')[2].partition(
            '"selector":'
        )[0]
        self.assertIn('"path": "AGENTS.md"', selected_change_scope)
        self.assertIn('"status": "modified"', selected_change_scope)
        self.assertNotIn(b'"path":"AGENTS.md"', captured["changes"])
        self.assertIn(b"diff --git a/AGENTS.md b/AGENTS.md", captured["target_change"])
        self.assertIn(
            b"+Use the repository bootstrap before running the validation command.",
            captured["target_change"],
        )

        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertEqual(rendered["schema"], "ctx-agents-plan/v3")
        self.assertEqual(rendered["selector"]["resolved"], resolved_base)
        self.assertEqual(
            rendered["selector"]["changed_paths"],
            [],
        )
        self.assertEqual(
            rendered["target_change"],
            {
                "base_digest": "sha256:"
                + hashlib.sha256(CREATE_CONTENT.encode("utf-8")).hexdigest(),
                "complete": True,
                "current_digest": "sha256:"
                + hashlib.sha256(UPDATE_CONTENT.encode("utf-8")).hexdigest(),
                "patch_digest": rendered["target_change"]["patch_digest"],
                "path": "AGENTS.md",
                "selected": True,
                "selected_digest": "sha256:"
                + hashlib.sha256(UPDATE_CONTENT.encode("utf-8")).hexdigest(),
                "status": "modified",
                "truncated": False,
            },
        )
        self.assertRegex(
            rendered["target_change"]["patch_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_target_only_working_change_invokes_model_and_can_no_op(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "no-op",
                evidence=("AGENTS.md",),
                assessments=(
                    _assessment("AGENTS.md", "already-covered"),
                ),
            )
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)

        self.assertEqual(plan.selector["kind"], "working")
        self.assertEqual(
            plan.selector["changed_paths"],
            [],
        )
        self.assertTrue(plan.target_change["selected"])
        self.assertEqual(
            tuple(item.path for item in reviewed.review.assessments),
            ("AGENTS.md",),
        )
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)

    def test_target_only_staged_change_invokes_model_and_can_no_op(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        self._git("add", "AGENTS.md")

        reviewed = self._review_with_payload(
            self._payload(
                "no-op",
                evidence=("AGENTS.md",),
                assessments=(
                    _assessment("AGENTS.md", "already-covered"),
                ),
            ),
            staged=True,
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)

        self.assertEqual(plan.selector["kind"], "staged")
        self.assertEqual(
            plan.selector["changed_paths"],
            [],
        )
        self.assertTrue(plan.target_change["selected"])
        self.assertEqual(
            tuple(item.path for item in reviewed.review.assessments),
            ("AGENTS.md",),
        )
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")

    def test_hidden_worktree_target_digest_mismatch_cannot_support_no_op(self) -> None:
        self._add_existing_agents()
        self._git("update-index", "--assume-unchanged", "AGENTS.md")
        (self.project / "AGENTS.md").write_text(UPDATE_CONTENT, encoding="utf-8")
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        self.assertNotIn("AGENTS.md", self._git("diff", "--name-only").stdout)

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(self._payload("no-op"))

        self.assertEqual(raised.exception.code, "agents.git-index-flags")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_hidden_staged_target_digest_mismatch_cannot_support_no_op(self) -> None:
        self._add_existing_agents()
        self._git("update-index", "--assume-unchanged", "AGENTS.md")
        (self.project / "AGENTS.md").write_text(UPDATE_CONTENT, encoding="utf-8")
        (self.project / "app.py").write_text("VALUE = 'staged'\n", encoding="utf-8")
        self._git("add", "app.py")
        self.assertNotIn(
            "AGENTS.md",
            self._git("diff", "--cached", "--name-only").stdout,
        )

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(self._payload("no-op"), staged=True)

        self.assertEqual(raised.exception.code, "agents.git-index-flags")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_skip_worktree_target_is_rejected_before_review(self) -> None:
        self._add_existing_agents()
        self._git("update-index", "--skip-worktree", "AGENTS.md")

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(self.project)

        codex.assert_not_called()
        self.assertEqual(raised.exception.code, "agents.git-index-flags")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_skip_worktree_non_target_in_scope_is_rejected_before_review(self) -> None:
        self._add_existing_agents()
        self._git("update-index", "--skip-worktree", "app.py")

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(self.project)

        codex.assert_not_called()
        self.assertEqual(raised.exception.code, "agents.git-index-flags")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_target_only_run_change_invokes_model_and_can_no_op(self) -> None:
        self._add_existing_agents()
        seal_freshness(self.project)
        self._commit_all("fresh run baseline")
        run = begin_run(self.project, task="update durable agent guidance")
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "no-op",
                evidence=("AGENTS.md",),
                assessments=(
                    _assessment("AGENTS.md", "already-covered"),
                ),
            ),
            run_id=run.run_id,
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)

        self.assertEqual(plan.selector["kind"], "run")
        self.assertEqual(plan.selector["changed_paths"], [])
        self.assertTrue(plan.target_change["selected"])
        self.assertEqual(
            tuple((item.path, item.status) for item in reviewed.review.assessments),
            (("AGENTS.md", "already-covered"),),
        )
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")

    def test_run_rejects_target_dirty_before_immutable_baseline(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        run = begin_run(self.project, task="change application behavior")
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with mock.patch.object(agent_instructions, "_run_codex") as codex:
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(
                    self.project,
                    run_id=run.run_id,
                )

        codex.assert_not_called()
        self.assertEqual(raised.exception.code, "agents.run-unattributable")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_no_op_requires_an_assessment_for_every_selected_change(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        (self.project / "README.md").write_text("changed documentation\n", encoding="utf-8")
        payload = self._payload(
            "no-op",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "implementation-only"),
            ),
        )

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(payload)

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_already_covered_rejects_source_only_assessment_evidence(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "no-op",
                    evidence=("app.py",),
                    assessments=(
                        _assessment(
                            "app.py",
                            "already-covered",
                            evidence=("app.py",),
                        ),
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_already_covered_is_forbidden_when_target_is_missing(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "review-required",
                    evidence=("app.py",),
                    assessments=(
                        _assessment("app.py", "already-covered"),
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_complete_exhaustive_no_op_is_accepted(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        (self.project / "README.md").write_text("changed documentation\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "no-op",
                evidence=("AGENTS.md", "app.py", "README.md"),
                assessments=(
                    _assessment("app.py", "implementation-only"),
                    _assessment(
                        "README.md",
                        "already-covered",
                        evidence=("AGENTS.md", "README.md"),
                    ),
                ),
            )
        )

        self.assertEqual(reviewed.review.disposition, "no-op")
        self.assertEqual(
            tuple((item.path, item.status) for item in reviewed.review.assessments),
            (
                ("README.md", "already-covered"),
                ("app.py", "implementation-only"),
            ),
        )
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "unchanged")

    def test_mixed_source_and_target_changes_require_exhaustive_assessments(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")

        reviewed = self._review_with_payload(
            self._payload(
                "no-op",
                evidence=("AGENTS.md", "app.py"),
                assessments=(
                    _assessment("AGENTS.md", "already-covered"),
                    _assessment("app.py", "implementation-only"),
                ),
            )
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)

        self.assertEqual(
            plan.selector["changed_paths"],
            [
                {"path": "app.py", "status": "modified"},
            ],
        )
        self.assertTrue(plan.target_change["selected"])
        self.assertEqual(
            tuple((item.path, item.status) for item in reviewed.review.assessments),
            (
                ("AGENTS.md", "already-covered"),
                ("app.py", "implementation-only"),
            ),
        )

    def test_target_race_during_target_only_review_saves_no_plan(self) -> None:
        self._add_existing_agents()
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        payload = self._payload(
            "no-op",
            evidence=("AGENTS.md",),
            assessments=(
                _assessment("AGENTS.md", "already-covered"),
            ),
        )

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del prepared, progress, prompt_suffix
            target.write_text(
                UPDATE_CONTENT + "\nA concurrent instruction change.\n",
                encoding="utf-8",
            )
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(self.project)

        self.assertEqual(raised.exception.code, "agents.target-changed")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_nested_target_only_change_routes_child_context_artifacts(self) -> None:
        child = self.project / "feature"
        child.mkdir()
        artifact = child / "contract.py"
        artifact.write_text("CONTRACT = 'canonical'\n", encoding="utf-8")
        context = child / ".ctx" / "context.yaml"
        context.parent.mkdir()
        context.write_text(
            "version: 1\n"
            "node:\n"
            "  id: feature\n"
            "  name: Feature\n"
            "  summary: Feature-specific operating context.\n"
            "artifacts:\n"
            "  - path: contract.py\n"
            "    role: Canonical feature contract.\n",
            encoding="utf-8",
        )
        target = child / "AGENTS.md"
        target.write_text(CREATE_CONTENT, encoding="utf-8")
        self._commit_all("add nested instruction scope")
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        payload = self._payload(
            "no-op",
            path="feature/AGENTS.md",
            evidence=("feature/AGENTS.md",),
            assessments=(
                _assessment("feature/AGENTS.md", "already-covered"),
            ),
        )
        captured: dict[str, object] = {}

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del progress, prompt_suffix
            captured["allowed_evidence"] = prepared.allowed_evidence
            captured["support_paths"] = prepared.support_paths
            captured["artifact_copied"] = (
                prepared.snapshot_root / "feature" / "contract.py"
            ).is_file()
            captured["context_copied"] = (
                prepared.snapshot_root / "feature" / ".ctx" / "context.yaml"
            ).is_file()
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            reviewed = agent_instructions.review_agent_instructions(child)

        self.assertEqual(reviewed.review.disposition, "no-op")
        self.assertIn("feature/contract.py", captured["allowed_evidence"])
        self.assertIn("feature/contract.py", captured["support_paths"])
        self.assertTrue(captured["artifact_copied"])
        self.assertTrue(captured["context_copied"])

    def test_truncated_non_target_patch_allows_update_from_complete_current_source(
        self,
    ) -> None:
        self._add_existing_agents()
        current_source = "".join(
            f"ADDED_{index:05d} = 'bounded evidence line'\n"
            for index in range(12_000)
        )
        (self.project / "app.py").write_text(current_source, encoding="utf-8")
        self._commit_all("large source change")

        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            ),
            since="HEAD^",
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))

        self.assertFalse(rendered["selector"]["complete"])
        self.assertTrue(rendered["selector"]["basis_complete"])
        self.assertTrue(rendered["selector"]["patch_truncated"])
        self.assertFalse(rendered["change_evidence_complete"])
        self.assertTrue(rendered["current_evidence_complete"])
        self.assertTrue(rendered["target_change"]["complete"])
        applied = agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(applied.action, "updated")
        self.assertEqual(
            (self.project / "AGENTS.md").read_text(encoding="utf-8"),
            UPDATE_CONTENT,
        )

    def test_truncated_patch_review_gets_one_isolated_correction_pass(self) -> None:
        self._prepare_truncated_non_target_review()
        first = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        second = self._payload(
            "update",
            content=UPDATE_CONTENT,
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "requires-update"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex((first, second))
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )

        self.assertEqual(reviewed.review.disposition, "update")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        records = [
            json.loads(line)
            for line in record_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["cwd"], records[1]["cwd"])
        first_arguments = records[0]["argv"]
        second_arguments = records[1]["argv"]
        self.assertEqual(
            first_arguments[first_arguments.index("-C") + 1],
            second_arguments[second_arguments.index("-C") + 1],
        )
        self.assertIn(
            'permissions.ctx-agents.filesystem={ ":minimal" = "read", '
            '":workspace_roots" = { "." = "read" } }',
            first_arguments,
        )
        self.assertIn(
            'permissions.ctx-agents.filesystem={ ":minimal" = "read", '
            '":workspace_roots" = { "." = "read" } }',
            second_arguments,
        )
        result_paths = [Path(record["result"]) for record in records]
        schema_paths = [
            Path(arguments[arguments.index("--output-schema") + 1])
            for arguments in (first_arguments, second_arguments)
        ]
        state_paths = [
            Path(
                json.loads(
                    next(
                        value.split("=", 1)[1]
                        for value in arguments
                        if value.startswith("sqlite_home=")
                    )
                )
            )
            for arguments in (first_arguments, second_arguments)
        ]
        for paths in (result_paths, schema_paths, state_paths):
            self.assertEqual(len(set(paths)), 2)
            self.assertEqual(
                [path.parent.name for path in paths],
                ["codex-attempt-1", "codex-attempt-2"],
            )
        self.assertNotIn("# One-time bounded correction", records[0]["prompt"])
        self.assertTrue(records[1]["prompt"].startswith(records[0]["prompt"]))
        self.assertIn("# One-time bounded correction", records[1]["prompt"])
        self.assertIn(
            'return `content: ""` plus exact unique old/new edits',
            records[1]["prompt"],
        )
        self.assertIn(
            "current target itself proves the subject-matter categories",
            records[1]["prompt"],
        )
        self.assertIn(
            "absence of prewritten replacement wording",
            records[1]["prompt"],
        )
        plans = tuple((self.ctx_home / "agents-plans").glob("*.json"))
        self.assertEqual(plans, (self.ctx_home / "agents-plans" / f"{reviewed.plan_id}.json",))

    def test_incomplete_first_response_can_be_corrected_to_update(self) -> None:
        self._prepare_truncated_non_target_review()
        incomplete = self._payload(
            "no-op",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "implementation-only"),
            ),
        )
        update = self._payload(
            "update",
            content=UPDATE_CONTENT,
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "requires-update"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex((incomplete, update))
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )

        self.assertEqual(reviewed.review.disposition, "update")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            2,
        )
        self.assertEqual(
            len(tuple((self.ctx_home / "agents-plans").glob("*.json"))),
            1,
        )

    def test_second_review_required_response_is_saved_and_blocked(self) -> None:
        self._prepare_truncated_non_target_review()
        review_required = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex(
                (review_required, review_required)
            )
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )

        self.assertEqual(reviewed.review.disposition, "review-required")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            len(tuple((self.ctx_home / "agents-plans").glob("*.json"))),
            1,
        )
        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(raised.exception.code, "agents.review-required")

    def test_invalid_second_correction_response_fails_without_a_plan(self) -> None:
        self._prepare_truncated_non_target_review()
        first = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        invalid: dict[str, object] = {
            "reviews": [],
            "summary": "The correction response is structurally invalid.",
        }
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex((first, invalid))
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(
                    self.project,
                    since="HEAD^",
                )

        self.assertEqual(raised.exception.code, "agents.agent-output-invalid")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            2,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_complete_evidence_review_required_does_not_get_a_correction_pass(
        self,
    ) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        review_required = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        unexpected_retry = self._payload(
            "update",
            content=UPDATE_CONTENT,
            assessments=(
                _assessment("app.py", "requires-update"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex(
                (review_required, unexpected_retry)
            )
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(self.project)

        self.assertEqual(reviewed.review.disposition, "review-required")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "1")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            1,
        )

    def test_incomplete_current_evidence_does_not_get_a_correction_pass(self) -> None:
        self._add_existing_agents()
        (self.project / "opaque.py").write_bytes(b"\0" * 1_024)
        review_required = self._payload(
            "review-required",
            evidence=("README.md",),
            assessments=(
                _assessment(
                    "opaque.py",
                    "insufficient-evidence",
                    evidence=("README.md",),
                ),
            ),
        )
        unexpected_retry = self._payload(
            "update",
            content=UPDATE_CONTENT,
            evidence=("README.md",),
            assessments=(
                _assessment(
                    "opaque.py",
                    "requires-update",
                    evidence=("README.md",),
                ),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex(
                (review_required, unexpected_retry)
            )
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
            },
        ):
            reviewed = agent_instructions.review_agent_instructions(self.project)

        self.assertEqual(reviewed.review.disposition, "review-required")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "1")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            1,
        )

    def test_source_race_after_correction_is_rejected_without_a_plan(self) -> None:
        source = self._prepare_truncated_non_target_review()
        first = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        second = self._payload(
            "update",
            content=UPDATE_CONTENT,
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "requires-update"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex((first, second))
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
                "FAKE_AGENTS_RACE_ATTEMPT": "1",
                "FAKE_AGENTS_RACE_PATH": str(source),
                "FAKE_AGENTS_RACE_CONTENT": "VALUE = 'raced after correction'\n",
            },
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(
                    self.project,
                    since="HEAD^",
                )

        self.assertEqual(raised.exception.code, "agents.project-changed")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            2,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_target_race_after_correction_is_rejected_without_a_plan(self) -> None:
        self._prepare_truncated_non_target_review()
        target = self.project / "AGENTS.md"
        first = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        second = self._payload(
            "update",
            content=UPDATE_CONTENT,
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "requires-update"),
            ),
        )
        executable, record_path, results_path, counter_path = (
            self._install_sequenced_fake_codex((first, second))
        )

        with mock.patch.dict(
            os.environ,
            {
                "CTX_CODEX": str(executable),
                "FAKE_AGENTS_SEQUENCE_RECORD": str(record_path),
                "FAKE_AGENTS_SEQUENCE_RESULTS": str(results_path),
                "FAKE_AGENTS_SEQUENCE_COUNTER": str(counter_path),
                "FAKE_AGENTS_RACE_ATTEMPT": "1",
                "FAKE_AGENTS_RACE_PATH": str(target),
                "FAKE_AGENTS_RACE_CONTENT": UPDATE_CONTENT,
            },
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.review_agent_instructions(
                    self.project,
                    since="HEAD^",
                )

        self.assertEqual(raised.exception.code, "agents.target-changed")
        self.assertEqual(counter_path.read_text(encoding="utf-8"), "2")
        self.assertEqual(
            len(record_path.read_text(encoding="utf-8").splitlines()),
            2,
        )
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_truncated_change_evidence_cannot_support_no_op(self) -> None:
        self._add_existing_agents()
        current_source = "".join(
            f"ADDED_{index:05d} = 'bounded evidence line'\n"
            for index in range(12_000)
        )
        (self.project / "app.py").write_text(current_source, encoding="utf-8")
        self._commit_all("large source change")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "no-op",
                    evidence=("app.py",),
                    assessments=(
                        _assessment("app.py", "implementation-only"),
                    ),
                ),
                since="HEAD^",
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        self.assertFalse((self.ctx_home / "agents-plans").exists())

    def test_deleted_selected_path_forces_review_required(self) -> None:
        self._add_existing_agents()
        deleted = self.project / "obsolete.py"
        deleted.write_text("VALUE = 'obsolete'\n", encoding="utf-8")
        self._commit_all("add source that will be deleted")
        deleted.unlink()
        assessment = _assessment(
            "obsolete.py",
            "insufficient-evidence",
            evidence=("README.md",),
        )

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    content=UPDATE_CONTENT,
                    evidence=("README.md",),
                    assessments=(assessment,),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        reviewed = self._review_with_payload(
            self._payload(
                "review-required",
                evidence=("README.md",),
                assessments=(assessment,),
            )
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertTrue(rendered["change_evidence_complete"])
        self.assertFalse(rendered["current_evidence_complete"])
        self.assertEqual(reviewed.review.disposition, "review-required")
        with self.assertRaises(CtxError) as apply_raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)
        self.assertEqual(apply_raised.exception.code, "agents.review-required")

    def test_uncopied_selected_change_cannot_support_no_op(self) -> None:
        self._add_existing_agents()
        opaque = self.project / "opaque.py"
        opaque.write_bytes(b"\0" * 1_024)
        assessment = _assessment(
            "opaque.py",
            "implementation-only",
            evidence=("README.md",),
        )

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "no-op",
                    evidence=("README.md",),
                    assessments=(assessment,),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        reviewed = self._review_with_payload(
            self._payload(
                "review-required",
                evidence=("README.md",),
                assessments=(
                    _assessment(
                        "opaque.py",
                        "insufficient-evidence",
                        evidence=("README.md",),
                    ),
                ),
            )
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertTrue(rendered["change_evidence_complete"])
        self.assertFalse(rendered["current_evidence_complete"])
        self.assertEqual(reviewed.review.disposition, "review-required")

    def test_truncated_target_delta_forces_review_required(self) -> None:
        self._add_existing_agents()
        large_target = "# Repository instructions\n\n" + "".join(
            f"- Durable operating rule {index:05d} applies.\n"
            for index in range(4_500)
        )
        encoded = large_target.encode("utf-8")
        self.assertGreater(
            len(encoded),
            agent_instructions.MAX_AGENTS_CHANGE_EVIDENCE_BYTES,
        )
        self.assertLess(len(encoded), agent_instructions.MAX_AGENTS_FILE_BYTES)
        (self.project / "AGENTS.md").write_text(large_target, encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            self._review_with_payload(
                self._payload(
                    "update",
                    edits=(
                        {
                            "old": "- Durable operating rule 02250 applies.\n",
                            "new": "- Durable operating rule 02250 requires validation.\n",
                        },
                    ),
                    evidence=("AGENTS.md",),
                    assessments=(
                        _assessment("AGENTS.md", "requires-update"),
                    ),
                )
            )

        self.assertEqual(raised.exception.code, "agents.agent-output-incomplete")
        reviewed = self._review_with_payload(
            self._payload(
                "review-required",
                evidence=("AGENTS.md",),
                assessments=(
                    _assessment("AGENTS.md", "insufficient-evidence"),
                ),
            )
        )
        rendered = json.loads(agent_instructions.render_agents_plan(reviewed.plan_id))
        self.assertTrue(rendered["target_change"]["truncated"])
        self.assertFalse(rendered["target_change"]["complete"])
        self.assertFalse(rendered["change_evidence_complete"])
        self.assertTrue(rendered["current_evidence_complete"])
        self.assertEqual(reviewed.review.disposition, "review-required")

    def test_existing_update_is_idempotent_when_target_already_matches_proposal(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")

        inventory = agent_instructions.inventory_repository(self.project)
        root_fd = agent_instructions._open_directory_no_follow(plan.root)
        self.assertIsNotNone(root_fd)
        try:
            full_fingerprint = agent_instructions._fingerprint_eligible_evidence(
                inventory,
                root_fd,
            )
            non_target_fingerprint = agent_instructions._fingerprint_eligible_evidence(
                inventory,
                root_fd,
                exclude_paths=frozenset({"AGENTS.md"}),
            )
        finally:
            os.close(root_fd)
        self.assertNotEqual(full_fingerprint, plan.evidence_fingerprint)
        self.assertEqual(non_target_fingerprint, plan.verification_fingerprint)

        first = agent_instructions.apply_agents_plan(reviewed.plan_id)
        second = agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(first.action, "unchanged")
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)

    def test_idempotent_apply_rejects_source_race_before_early_return(self) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        original_collect = agent_instructions._collect_target_change
        raced = False

        def race_after_target_precheck(*args: object, **kwargs: object) -> object:
            nonlocal raced
            change = original_collect(*args, **kwargs)
            if not raced:
                raced = True
                source.write_text("VALUE = 'raced'\n", encoding="utf-8")
            return change

        with mock.patch.object(
            agent_instructions,
            "_collect_target_change",
            side_effect=race_after_target_precheck,
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertTrue(raced)
        self.assertIn(
            raised.exception.code,
            {"agents.plan-stale", "agents.project-changed"},
        )
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'raced'\n")

    def test_idempotent_apply_rejects_inventory_that_becomes_incomplete(self) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        target_identity = (
            target.stat().st_dev,
            target.stat().st_ino,
            target.stat().st_mtime_ns,
        )
        inventory_checks = 0

        def incomplete_after_precheck(inventory: object) -> tuple[str, ...]:
            nonlocal inventory_checks
            del inventory
            inventory_checks += 1
            return () if inventory_checks == 1 else ("forced incomplete inventory",)

        with mock.patch.object(
            agent_instructions,
            "inventory_evidence_reasons",
            side_effect=incomplete_after_precheck,
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(inventory_checks, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)
        self.assertEqual(
            (
                target.stat().st_dev,
                target.stat().st_ino,
                target.stat().st_mtime_ns,
            ),
            target_identity,
        )
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'after'\n")

    def test_first_write_rolls_back_when_inventory_becomes_incomplete(self) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        target = self.project / "AGENTS.md"
        original_mode = stat.S_IMODE(target.stat().st_mode)
        inventory_checks = 0

        def incomplete_after_write(inventory: object) -> tuple[str, ...]:
            nonlocal inventory_checks
            del inventory
            inventory_checks += 1
            return () if inventory_checks == 1 else ("forced incomplete inventory",)

        with mock.patch.object(
            agent_instructions,
            "inventory_evidence_reasons",
            side_effect=incomplete_after_write,
        ):
            with self.assertRaises(CtxError) as raised:
                agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.project-changed")
        self.assertEqual(inventory_checks, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), original_mode)
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'after'\n")
        self.assertEqual(
            tuple(target.parent.glob(".AGENTS.md.*.tmp")),
            (),
        )

    def test_apply_rejects_drift_in_either_completeness_dimension_before_write(
        self,
    ) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        plan = agent_instructions._load_plan(reviewed.plan_id)
        self.assertTrue(plan.change_evidence_complete)
        self.assertTrue(plan.current_evidence_complete)
        target = self.project / "AGENTS.md"
        target_identity = (
            target.stat().st_dev,
            target.stat().st_ino,
            target.stat().st_mtime_ns,
        )

        for recomputed in ((False, True), (True, False)):
            with self.subTest(recomputed=recomputed):
                with mock.patch.object(
                    agent_instructions,
                    "_apply_completeness_flags",
                    return_value=recomputed,
                ):
                    with self.assertRaises(CtxError) as raised:
                        agent_instructions.apply_agents_plan(reviewed.plan_id)

                self.assertEqual(raised.exception.code, "agents.plan-stale")
                self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)
                self.assertEqual(
                    (
                        target.stat().st_dev,
                        target.stat().st_ino,
                        target.stat().st_mtime_ns,
                    ),
                    target_identity,
                )
                self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'after'\n")

    def test_first_write_rolls_back_if_either_completeness_dimension_drifts(
        self,
    ) -> None:
        self._add_existing_agents()
        source = self.project / "app.py"
        source.write_text("VALUE = 'after'\n", encoding="utf-8")
        target = self.project / "AGENTS.md"
        original_mode = stat.S_IMODE(target.stat().st_mode)

        for recomputed_after_write in ((False, True), (True, False)):
            with self.subTest(recomputed_after_write=recomputed_after_write):
                reviewed = self._review_with_payload(
                    self._payload(
                        "update",
                        content=UPDATE_CONTENT,
                        assessments=(
                            _assessment("app.py", "requires-update"),
                        ),
                    )
                )
                calls = 0

                def completeness_after_write(
                    selector: object,
                    target_change: object,
                    inventory: object,
                ) -> tuple[bool, bool]:
                    nonlocal calls
                    del selector, target_change, inventory
                    calls += 1
                    return (True, True) if calls == 1 else recomputed_after_write

                with mock.patch.object(
                    agent_instructions,
                    "_apply_completeness_flags",
                    side_effect=completeness_after_write,
                ):
                    with self.assertRaises(CtxError) as raised:
                        agent_instructions.apply_agents_plan(reviewed.plan_id)

                self.assertEqual(raised.exception.code, "agents.project-changed")
                self.assertEqual(calls, 2)
                self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), original_mode)
                self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 'after'\n")
                self.assertEqual(tuple(target.parent.glob(".AGENTS.md.*.tmp")), ())

    def test_staged_idempotent_apply_rejects_different_target_bytes_in_index(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'staged'\n", encoding="utf-8")
        self._git("add", "app.py")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            ),
            staged=True,
        )
        target = self.project / "AGENTS.md"
        malicious = "# Different staged instructions\n\nDo something else.\n"
        target.write_text(malicious, encoding="utf-8")
        self._git("add", "AGENTS.md")
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        self.assertEqual(self._git("show", ":AGENTS.md").stdout, malicious)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)
        self.assertEqual(self._git("show", ":AGENTS.md").stdout, malicious)

    def test_idempotent_apply_rejects_exact_bytes_with_wrong_target_mode(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")
        target.chmod(0o777)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o777)

    def test_idempotent_apply_rejects_new_unsafe_target_index_flag(self) -> None:
        self._add_existing_agents()
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "update",
                content=UPDATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        self._git("update-index", "--assume-unchanged", "AGENTS.md")
        target = self.project / "AGENTS.md"
        target.write_text(UPDATE_CONTENT, encoding="utf-8")

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(target.read_text(encoding="utf-8"), UPDATE_CONTENT)

    def test_idempotent_create_rejects_target_that_became_ignored(self) -> None:
        (self.project / "app.py").write_text("VALUE = 'after'\n", encoding="utf-8")
        reviewed = self._review_with_payload(
            self._payload(
                "create",
                content=CREATE_CONTENT,
                evidence=("app.py",),
                assessments=(
                    _assessment("app.py", "requires-update"),
                ),
            )
        )
        target = self.project / "AGENTS.md"
        target.write_text(CREATE_CONTENT, encoding="utf-8")
        exclude = self.project / ".git" / "info" / "exclude"
        exclude.write_text(
            exclude.read_text(encoding="utf-8") + "\nAGENTS.md\n",
            encoding="utf-8",
        )

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-stale")
        self.assertEqual(target.read_text(encoding="utf-8"), CREATE_CONTENT)

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

    def test_since_review_truncates_large_patch_and_copies_current_source(self) -> None:
        current_source = "".join(
            f"ADDED_{index:05d} = 'bounded evidence line'\n"
            for index in range(12_000)
        )
        (self.project / "app.py").write_text(current_source, encoding="utf-8")
        self._commit_all("large source change")
        resolved_base = self._git("rev-parse", "HEAD^").stdout.strip()
        payload = self._payload(
            "review-required",
            evidence=("app.py",),
            assessments=(
                _assessment("app.py", "insufficient-evidence"),
            ),
        )
        captured_change_evidence: list[bytes] = []
        captured_source: list[bytes] = []
        captured_prompt: list[str] = []

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del progress
            captured_change_evidence.append(
                (prepared.snapshot_root / agent_instructions.AGENTS_CHANGE_PATH).read_bytes()
            )
            captured_source.append((prepared.snapshot_root / "app.py").read_bytes())
            captured_prompt.append(
                agent_instructions.render_agents_review_prompt(prepared) + prompt_suffix
            )
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )

        self.assertEqual(reviewed.review.disposition, "review-required")
        self.assertEqual(
            captured_source,
            [current_source.encode("utf-8"), current_source.encode("utf-8")],
        )
        self.assertIn(b"ADDED_11999", captured_source[0])
        self.assertEqual(len(captured_change_evidence), 2)
        self.assertEqual(captured_change_evidence[0], captured_change_evidence[1])
        change_evidence = captured_change_evidence[0]
        self.assertLessEqual(
            len(change_evidence),
            agent_instructions.MAX_AGENTS_CHANGE_EVIDENCE_BYTES,
        )
        self.assertIn(b"# selector: since", change_evidence)
        self.assertIn(
            f"# resolved_base: {resolved_base}".encode("ascii"),
            change_evidence,
        )
        self.assertIn(b"# limitation:", change_evidence)
        self.assertIn(b"hard byte limit", change_evidence)
        self.assertIn(b"truncated", change_evidence)
        self.assertNotIn(b"ADDED_11999", change_evidence)
        self.assertEqual(len(captured_prompt), 2)
        self.assertIn('"argument": "HEAD^"', captured_prompt[0])
        self.assertIn(f'"resolved": "{resolved_base}"', captured_prompt[0])
        self.assertIn("truncated", captured_prompt[0])
        self.assertIn("# One-time bounded correction", captured_prompt[1])

    def test_change_evidence_bounds_quote_heavy_unicode_path_header(self) -> None:
        changed_paths = []
        quote_heavy = '"' * 88
        unicode_heavy = "λ" * 70
        padding = "x" * 8
        for index in range(250):
            name = f"{index:03d}-{quote_heavy}{unicode_heavy}{padding}.py"
            (self.project / name).write_text("VALUE = True\n", encoding="utf-8")
            changed_paths.append(name)
        captured_change_evidence: list[bytes] = []
        payload = self._payload(
            "review-required",
            evidence=("README.md",),
            assessments=tuple(
                _assessment(
                    path,
                    "insufficient-evidence",
                    evidence=("README.md",),
                )
                for path in changed_paths
            ),
        )

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del progress, prompt_suffix
            captured_change_evidence.append(
                (prepared.snapshot_root / agent_instructions.AGENTS_CHANGE_PATH).read_bytes()
            )
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            reviewed = agent_instructions.review_agent_instructions(self.project)

        self.assertEqual(reviewed.review.disposition, "review-required")
        self.assertEqual(len(captured_change_evidence), 1)
        change_evidence = captured_change_evidence[0]
        self.assertLessEqual(
            len(change_evidence),
            agent_instructions.MAX_AGENTS_CHANGE_EVIDENCE_BYTES,
        )
        header = change_evidence.partition(b"\n\n")[0].decode("utf-8")
        self.assertIn("omitted", header.casefold())
        self.assertIn("changed", header.casefold())
        self.assertIn("path", header.casefold())
        self.assertGreater(
            sum(len(path.encode("utf-8")) for path in changed_paths),
            50_000,
        )

    def test_truncated_plan_samples_later_path_fairly_and_requires_review(self) -> None:
        current_source = "".join(
            f"ADDED_{index:05d} = 'bounded evidence line'\n"
            for index in range(12_000)
        )
        large_source = self.project / "a-large.py"
        large_source.write_text(current_source, encoding="utf-8")
        later_source = self.project / "z-later.py"
        later_source.write_text("VALUE = 'before review'\n", encoding="utf-8")
        self._commit_all("large source change")
        payload = self._payload(
            "review-required",
            evidence=("a-large.py", "z-later.py"),
            assessments=(
                _assessment("a-large.py", "insufficient-evidence"),
                _assessment("z-later.py", "insufficient-evidence"),
            ),
        )
        captured_change_evidence: list[bytes] = []

        def fake_runner(
            prepared: agent_instructions._PreparedReview,
            work_directory: Path,
            *,
            progress: object = None,
            prompt_suffix: str = "",
        ) -> Path:
            del progress, prompt_suffix
            captured_change_evidence.append(
                (prepared.snapshot_root / agent_instructions.AGENTS_CHANGE_PATH).read_bytes()
            )
            result = work_directory / "fake-agents-result.json"
            result.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(agent_instructions, "_run_codex", side_effect=fake_runner):
            reviewed = agent_instructions.review_agent_instructions(
                self.project,
                since="HEAD^",
            )
        saved_plan = agent_instructions._load_plan(reviewed.plan_id)

        self.assertIsNotNone(saved_plan.selector["limitation"])
        self.assertIn("truncated", str(saved_plan.selector["limitation"]))
        self.assertEqual(len(captured_change_evidence), 2)
        self.assertEqual(captured_change_evidence[0], captured_change_evidence[1])
        retained_patch = captured_change_evidence[0].partition(b"\n\n")[2]
        self.assertIn(b"diff --git a/z-later.py", retained_patch)
        self.assertIn(b"ctx path diff truncated", retained_patch)
        later_source.write_text("VALUE = 'after review'\n", encoding="utf-8")
        current_selector = agent_instructions._recompute_plan_selector(saved_plan)
        self.assertNotEqual(
            current_selector.fingerprint,
            saved_plan.selector_fingerprint,
        )

        with self.assertRaises(CtxError) as raised:
            agent_instructions.apply_agents_plan(reviewed.plan_id)

        self.assertEqual(raised.exception.code, "agents.review-required")
        self.assertFalse((self.project / "AGENTS.md").exists())

    def test_fair_path_diff_fallback_shares_deadline_and_bounds_commands(self) -> None:
        calls: list[tuple[tuple[str, ...], float | None]] = []

        def fake_patch(
            root: Path,
            arguments: list[str],
            *,
            code: str,
            message: str,
            deadline: float | None = None,
        ) -> tuple[bytes, bool]:
            del root, code, message
            calls.append((tuple(arguments), deadline))
            if deadline is None:
                return b"", True
            return f"diff for {arguments[-1]}\n".encode("utf-8"), False

        with mock.patch.object(
            agent_instructions,
            "_bounded_git_patch_output",
            side_effect=fake_patch,
        ), mock.patch.object(
            agent_instructions.time,
            "monotonic",
            return_value=100.0,
        ):
            patch, _digest, truncated = agent_instructions._git_patch(
                self.project,
                kind="working",
                base="HEAD",
                paths=("a.py", "b.py", "c.py"),
            )

        self.assertFalse(truncated)
        self.assertEqual(len(calls), 4)
        self.assertIsNone(calls[0][1])
        self.assertEqual(
            [deadline for _arguments, deadline in calls[1:]],
            [
                100.0 + agent_instructions.AGENTS_FAIR_PATCH_TOTAL_SECONDS,
            ]
            * 3,
        )
        self.assertIn(b"diff for a.py", patch)
        self.assertIn(b"diff for c.py", patch)

        calls.clear()
        bounded_paths = tuple(
            f"path-{index:03d}.py"
            for index in range(agent_instructions.MAX_AGENTS_FAIR_PATCH_COMMANDS + 1)
        )
        with mock.patch.object(
            agent_instructions,
            "_bounded_git_patch_output",
            side_effect=fake_patch,
        ), mock.patch.object(
            agent_instructions.time,
            "monotonic",
            return_value=200.0,
        ):
            bounded_patch, _digest, bounded_truncated = agent_instructions._git_patch(
                self.project,
                kind="working",
                base="HEAD",
                paths=bounded_paths,
            )

        self.assertTrue(bounded_truncated)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0][1])
        self.assertIn(
            f"1/{len(bounded_paths)}".encode("ascii"),
            bounded_patch,
        )

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

    def test_pre_v3_saved_plan_fails_closed(self) -> None:
        payload = self._valid_saved_plan_payload()
        self.assertEqual(payload["schema"], "ctx-agents-plan/v3")
        payload["schema"] = "ctx-agents-plan/v2"
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_saved_plan_rejects_provider_edit_transport_fields(self) -> None:
        payload = self._valid_saved_plan_payload()
        review = payload["review"]
        self.assertIsInstance(review, dict)
        review["edits"] = []
        plan_id = self._write_content_addressed_plan(payload)

        with self.assertRaises(CtxError) as raised:
            agent_instructions.render_agents_plan(plan_id)

        self.assertEqual(raised.exception.code, "agents.plan-invalid")

    def test_apply_revalidates_saved_completeness_dimensions(self) -> None:
        for field in ("change_evidence_complete", "current_evidence_complete"):
            with self.subTest(field=field):
                payload = self._valid_saved_plan_payload()
                self.assertIs(payload[field], True)
                payload[field] = False
                plan_id = self._write_content_addressed_plan(payload)

                with self.assertRaises(CtxError) as raised:
                    agent_instructions.apply_agents_plan(plan_id)

                self.assertEqual(raised.exception.code, "agents.plan-invalid")
                self.assertFalse((self.project / "AGENTS.md").exists())

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
