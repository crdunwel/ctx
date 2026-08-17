from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx import reconciliation
from ctx.cli import _safe_display
from ctx.freshness import seal_freshness
from ctx.retrofit_agent import MAX_AGENT_OUTPUT_BYTES, MAX_PROPOSED_MANIFESTS
from ctx.yamlio import MAX_MANIFEST_BYTES


class ReconcileCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.ctx_home = self.base / "ctx-home"
        self.home.mkdir()
        self.project = self.base / "reconcile-project"
        self.project.mkdir()
        self.source = self.project / "app.py"
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        initialized = self.run_ctx(
            "init",
            str(self.project),
            "--id",
            "reconcile-project",
            "--name",
            "Reconcile Project",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        seal_freshness(self.project)

    def run_ctx(
        self, *arguments: str, extra_environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(self.home)
        environment["CTX_HOME"] = str(self.ctx_home)
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=self.project if self.project.exists() else self.base,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def fake_codex(self) -> tuple[Path, dict[str, str]]:
        directory = self.base / "bin"
        directory.mkdir(exist_ok=True)
        executable = directory / "codex"
        script = f'''#!{Path(sys.executable).resolve()}
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
result = Path(args[args.index("--output-last-message") + 1])
workspace = Path(args[args.index("-C") + 1])
mode = os.environ.get("FAKE_RECONCILE_MODE", "ack")
record = os.environ.get("FAKE_RECONCILE_RECORD")
if record:
    Path(record).write_text(json.dumps(sorted(
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file()
    )), encoding="utf-8")
root_manifest = """version: 1
project:
  id: reconcile-project
  name: Reconcile Project
  aliases: []
node:
  id: root
  name: Reconcile Project
  summary: Durable purpose updated from current source evidence.
"""
if mode == "update":
    payload = {{
        "manifests": [{{"path": ".ctx/context.yaml", "content": root_manifest}}],
        "acknowledgements": [],
        "summary": "Updated durable root purpose.",
    }}
elif mode == "graph-invalid":
    invalid = root_manifest + "artifacts:\\n  - path: missing.py\\n    role: Missing source.\\n"
    payload = {{
        "manifests": [{{"path": ".ctx/context.yaml", "content": invalid}}],
        "acknowledgements": [],
        "summary": "Invalid proposal for rollback coverage.",
    }}
else:
    acknowledgement_uri = os.environ.get(
        "FAKE_RECONCILE_URI", "ctx://reconcile-project"
    )
    payload = {{
        "manifests": [],
        "acknowledgements": [{{
            "uri": acknowledgement_uri,
            "reason": "Implementation-only value change with no durable contract impact."
        }}],
        "summary": "Reviewed as implementation-only.",
    }}
result.write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")
'''
        executable.write_text(script, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return directory, {
            "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
        }

    def correction_fake_codex(self) -> tuple[Path, Path, dict[str, str]]:
        directory = self.base / "correction-bin"
        directory.mkdir(exist_ok=True)
        executable = directory / "codex"
        record = self.base / "reconcile-correction-invocations.jsonl"
        script = f'''#!{Path(sys.executable).resolve()}
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

arguments = sys.argv[1:]
prompt = sys.stdin.read()
workspace = Path(arguments[arguments.index("-C") + 1])
schema_path = Path(arguments[arguments.index("--output-schema") + 1])
result_path = Path(arguments[arguments.index("--output-last-message") + 1])
record_path = Path(os.environ["FAKE_RECONCILE_INVOCATIONS"])
live_root = Path(os.environ["FAKE_RECONCILE_LIVE_ROOT"])
mode = os.environ.get("FAKE_RECONCILE_CORRECTION_MODE", "valid-update")
attempt = 1
if record_path.exists():
    attempt += len(record_path.read_text(encoding="utf-8").splitlines())


def descriptor_kind(descriptor: int) -> str:
    mode_bits = os.fstat(descriptor).st_mode
    if stat.S_ISREG(mode_bits):
        return "regular"
    if stat.S_ISFIFO(mode_bits):
        return "pipe"
    if stat.S_ISCHR(mode_bits):
        return "character"
    return "other"


def snapshot(root: Path) -> list[list[object]]:
    records: list[list[object]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            records.append([
                relative,
                "file",
                stat.S_IMODE(metadata.st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            ])
        elif stat.S_ISDIR(metadata.st_mode):
            records.append([relative, "directory", stat.S_IMODE(metadata.st_mode)])
        elif stat.S_ISLNK(metadata.st_mode):
            records.append([relative, "symlink", os.readlink(path)])
        else:
            records.append([relative, "special", stat.S_IMODE(metadata.st_mode)])
    return records


snapshot_before = snapshot(workspace)
valid_manifest = """version: 1
project:
  id: reconcile-project
  name: Reconcile Project
  aliases: []
node:
  id: root
  name: Reconcile Project
  summary: Current source now establishes a durable bounded operating rule.
items:
  - id: bounded-operating-rule
    kind: invariant
    title: Bounded operating rule
    summary: Future changes must preserve the evidence-backed operating rule.
"""
invalid_summary_canary = "FIRST_INVALID_OUTPUT_CANARY_36ca42"
invalid_manifest = valid_manifest.replace(
    "Future changes must preserve the evidence-backed operating rule.",
    invalid_summary_canary + ("s" * (501 - len(invalid_summary_canary))),
)
graph_invalid_manifest = valid_manifest + """artifacts:
  - path: missing.py
    role: This source path does not exist.
"""
top_level_item_evidence = """artifacts:
  - path: tests/researchCoverage.test.ts
    role: Verifies exhaustive multi-signal source-ledger presentation.
  - path: tests/mapLayers.test.ts
    role: Verifies the allowlisted mapping from evidence types to map groups.
  - path: tests/affordableHousing.test.ts
    role: Verifies source wording and candidate-match limitations.
"""
item_evidence_manifest = """version: 1
project:
  id: reconcile-project
  name: Reconcile Project
  aliases: []
node:
  id: root
  name: Reconcile Project
  summary: Current source now establishes durable browser evidence rules.
""" + top_level_item_evidence + """items:
  - id: unavailable-states-remain-visible
    kind: invariant
    title: Unavailable states remain visible
    summary: Coverage signals remain distinct and visible.
    artifacts: [tests/researchCoverage.test.ts]
  - id: research-coverage-is-exhaustive
    kind: invariant
    title: Research coverage is exhaustive
    summary: Every source-ledger row maps to one visible domain.
    artifacts: [tests/researchCoverage.test.ts]
  - id: lazy-map-is-a-screening-projection
    kind: pattern
    title: Property map is a screening projection
    summary: Only allowlisted layer groups may be requested.
    artifacts: [tests/mapLayers.test.ts]
  - id: specialized-families-retain-source-meaning
    kind: invariant
    title: Specialized evidence retains source meaning
    summary: Affordable-housing evidence retains source limitations.
    artifacts: [tests/affordableHousing.test.ts]
"""
undeclared_item_evidence_manifest = item_evidence_manifest.replace(
    top_level_item_evidence,
    "",
)
adapter_prose_manifest = valid_manifest.replace(
    "Current source now establishes a durable bounded operating rule.",
    "Durable prose preserves the `.ctx-retrofit` adapter name as project context.",
)

if mode == "provider-failure":
    payload = None
elif mode == "surrogate-summary":
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": valid_manifest,
        }}],
        "acknowledgements": [],
        "summary": chr(0xD800),
    }}
elif mode == "surrogate-acknowledgement":
    payload = {{
        "manifests": [],
        "acknowledgements": [{{
            "uri": "ctx://reconcile-project",
            "reason": "Implementation-only " + chr(0xD800),
        }}],
        "summary": "Rejected unsafe acknowledgement text.",
    }}
elif mode == "unsafe-path":
    payload = {{
        "manifests": [{{"path": "../.ctx/context.yaml", "content": valid_manifest}}],
        "acknowledgements": [],
        "summary": "Unsafe path must not be retried.",
    }}
elif mode == "coverage-incomplete":
    payload = {{
        "manifests": [],
        "acknowledgements": [],
        "summary": "Affected scope was omitted.",
    }}
elif mode == "graph-invalid":
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": graph_invalid_manifest,
        }}],
        "acknowledgements": [],
        "summary": "Graph-invalid result must not be retried.",
    }}
elif mode in {{
    "undeclared-item-artifacts-once",
    "undeclared-item-artifacts-always",
}}:
    invalid = attempt == 1 or mode == "undeclared-item-artifacts-always"
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": (
                undeclared_item_evidence_manifest if invalid else item_evidence_manifest
            ),
        }}],
        "acknowledgements": [],
        "summary": "Proposed durable browser evidence rules.",
    }}
elif mode == "valid-preserve-adapter-prose":
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": adapter_prose_manifest,
        }}],
        "acknowledgements": [],
        "summary": "Preserved valid durable prose while updating the manifest.",
    }}
elif mode in {{"invalid-before-unsafe", "unsafe-before-invalid"}}:
    invalid_entry = {{"path": ".ctx/context.yaml", "content": invalid_manifest}}
    unsafe_entry = {{"path": "../.ctx/context.yaml", "content": valid_manifest}}
    payload = {{
        "manifests": (
            [invalid_entry, unsafe_entry]
            if mode == "invalid-before-unsafe"
            else [unsafe_entry, invalid_entry]
        ),
        "acknowledgements": [],
        "summary": "Fatal unsafe scope must win over local correction.",
    }}
elif mode == "invalid-with-duplicate-coverage":
    payload = {{
        "manifests": [
            {{"path": ".ctx/context.yaml", "content": invalid_manifest}},
            {{"path": ".ctx/context.yaml", "content": valid_manifest}},
        ],
        "acknowledgements": [],
        "summary": "Fatal duplicate coverage must win over local correction.",
    }}
elif mode == "invalid-with-generated-diff-reference":
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": invalid_manifest + """tracking:
  include:
    - .ctx-retrofit-reconcile-diff.patch
""",
        }}],
        "acknowledgements": [],
        "summary": "Generated evidence policy must win over local correction.",
    }}
elif mode == "invalid-with-adapter-reference":
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": invalid_manifest + """tracking:
  include:
    - .ctx-retrofit-evidence.json
""",
        }}],
        "acknowledgements": [],
        "summary": "Generated adapter policy must win over local correction.",
    }}
elif mode == "invalid-summary-then-missing-result" and attempt == 2:
    payload = None
else:
    invalid = mode in {{
        "invalid-summary-always",
        "invalid-summary-once",
        "invalid-summary-then-missing-result",
        "invalid-summary-with-manifest-race",
        "invalid-summary-with-source-race",
        "invalid-summary-then-source-race",
    }} and (attempt == 1 or mode == "invalid-summary-always")
    payload = {{
        "manifests": [{{
            "path": ".ctx/context.yaml",
            "content": invalid_manifest if invalid else valid_manifest,
        }}],
        "acknowledgements": [],
        "summary": "Proposed one evidence-backed durable update.",
    }}

transcript_canary = os.environ.get(
    "FAKE_RECONCILE_TRANSCRIPT_CANARY",
    "RECONCILE_PROVIDER_TRANSCRIPT_CANARY",
)
prompt_transcript_canary = "CTX_RECONCILE_PROMPT_VERSION=2"
result_transcript_canary = "RECONCILE_RESULT_TRANSCRIPT_CANARY_b25344"
print(
    "provider stdout " + prompt_transcript_canary + " "
    + result_transcript_canary + " " + transcript_canary + ("o" * 32_000)
)
print(
    "provider stderr " + prompt_transcript_canary + " "
    + result_transcript_canary + " " + transcript_canary + ("e" * 32_000),
    file=sys.stderr,
)
if payload is not None:
    result_path.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\\n",
        encoding="utf-8",
    )

if mode == "source-race" or (
    mode == "invalid-summary-with-source-race" and attempt == 1
) or (
    mode == "invalid-summary-then-source-race" and attempt == 2
):
    (live_root / "app.py").write_text(
        "CHANGED_DURING_REVIEW = True\\n", encoding="utf-8"
    )
if mode == "invalid-summary-with-manifest-race" and attempt == 1:
    live_manifest = live_root / ".ctx" / "context.yaml"
    live_manifest.write_text(
        live_manifest.read_text(encoding="utf-8").replace(
            "node:\\n  id: root\\n  name: Reconcile Project\\n",
            "node:\\n  id: root\\n  name: Reconcile Project\\n"
            "  summary: MANIFEST_RACE_CANARY_1cb282\\n",
        ),
        encoding="utf-8",
    )

configs = [
    arguments[index + 1]
    for index, value in enumerate(arguments[:-1])
    if value == "-c"
]
sqlite_value = next(value for value in configs if value.startswith("sqlite_home="))
invocation = {{
    "attempt": attempt,
    "argv": arguments,
    "prompt": prompt,
    "workspace": str(workspace),
    "schema_path": str(schema_path),
    "schema": json.loads(schema_path.read_text(encoding="utf-8")),
    "result_path": str(result_path),
    "sqlite_home": json.loads(sqlite_value.split("=", 1)[1]),
    "snapshot_before": snapshot_before,
    "snapshot_after": snapshot(workspace),
    "stdout_kind": descriptor_kind(sys.stdout.fileno()),
    "stderr_kind": descriptor_kind(sys.stderr.fileno()),
}}
with record_path.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(invocation, ensure_ascii=True, sort_keys=True) + "\\n")
if mode == "provider-failure":
    raise SystemExit(23)
'''
        executable.write_text(script, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return directory, record, {
            "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_RECONCILE_INVOCATIONS": str(record),
            "FAKE_RECONCILE_LIVE_ROOT": str(self.project.resolve()),
        }

    def read_correction_invocations(self, record: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in record.read_text(encoding="utf-8").splitlines()
        ]

    def create_item_evidence_files(self) -> None:
        tests = self.project / "tests"
        tests.mkdir(exist_ok=True)
        for name in (
            "researchCoverage.test.ts",
            "mapLayers.test.ts",
            "affordableHousing.test.ts",
        ):
            (tests / name).write_text("export {};\n", encoding="utf-8")

    def test_local_manifest_schema_error_gets_one_isolated_correction(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        source_canary = "RECONCILE_SOURCE_OUTPUT_CANARY_36e278"
        transcript_canary = "RECONCILE_TRANSCRIPT_CANARY_72bc84"
        self.source.write_text(source_canary + "\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment.update(
            {
                "FAKE_RECONCILE_CORRECTION_MODE": "invalid-summary-once",
                "FAKE_RECONCILE_TRANSCRIPT_CANARY": transcript_canary,
            }
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 manifest(s) updated", result.stdout)
        invocations = self.read_correction_invocations(record)
        self.assertEqual([item["attempt"] for item in invocations], [1, 2])
        self.assertEqual(
            {str(item["workspace"]) for item in invocations},
            {str(invocations[0]["workspace"])},
        )
        self.assertEqual(
            invocations[0]["snapshot_before"], invocations[1]["snapshot_before"]
        )
        for invocation in invocations:
            self.assertEqual(
                invocation["snapshot_before"], invocation["snapshot_after"]
            )
            self.assertEqual(invocation["stdout_kind"], "character")
            self.assertEqual(invocation["stderr_kind"], "character")
        self.assertEqual(
            len({str(item["schema_path"]) for item in invocations}), 2
        )
        self.assertEqual(
            len({str(item["result_path"]) for item in invocations}), 2
        )
        self.assertEqual(
            len({str(item["sqlite_home"]) for item in invocations}), 2
        )
        self.assertEqual(invocations[0]["schema"], invocations[1]["schema"])
        schema = invocations[0]["schema"]
        self.assertEqual(
            schema["properties"]["manifests"]["maxItems"],
            MAX_PROPOSED_MANIFESTS,
        )
        self.assertEqual(
            schema["properties"]["acknowledgements"]["maxItems"],
            MAX_PROPOSED_MANIFESTS,
        )

        first_prompt = str(invocations[0]["prompt"])
        correction_prompt = str(invocations[1]["prompt"])
        marker = "# One-time bounded proposal correction"
        self.assertNotIn(marker, first_prompt)
        self.assertIn(marker, correction_prompt)
        self.assertIn(
            "every node or\nitem summary has at most 500 characters",
            first_prompt,
        )
        self.assertIn(
            "acknowledgement reason must contain 1 to 500 characters including "
            "at least one\nnon-whitespace character",
            first_prompt,
        )
        self.assertIn(
            "The aggregate UTF-8 size of all proposed\nmanifest contents and the "
            "UTF-8 size of the complete JSON result file must\neach be at most "
            f"{MAX_AGENT_OUTPUT_BYTES} bytes.",
            first_prompt,
        )
        self.assertIn(
            f"at most {MAX_MANIFEST_BYTES}\nUTF-8 bytes, uses LF line endings "
            "with no carriage returns, and ends with a\nnewline",
            first_prompt,
        )
        self.assertIn("untrusted model output", correction_prompt)
        self.assertIn("local proposal-validation failure", correction_prompt)
        self.assertIn("500-character limit", correction_prompt)
        self.assertIn("same read-only snapshot", correction_prompt)
        self.assertNotIn("FIRST_INVALID_OUTPUT_CANARY_36ca42", correction_prompt)
        self.assertNotIn(transcript_canary, correction_prompt)
        self.assertLessEqual(len(correction_prompt), len(first_prompt) + 4_096)

        combined_output = result.stdout + result.stderr
        self.assertNotIn("CTX_RECONCILE_PROMPT_VERSION=2", combined_output)
        self.assertNotIn("RECONCILE_RESULT_TRANSCRIPT_CANARY_b25344", combined_output)
        self.assertNotIn(source_canary, combined_output)
        self.assertNotIn(transcript_canary, combined_output)
        self.assertNotIn("FIRST_INVALID_OUTPUT_CANARY_36ca42", combined_output)
        self.assertLess(len(result.stdout), 20_000)
        self.assertLess(len(result.stderr), 20_000)
        self.assertNotEqual(manifest.read_bytes(), original_manifest)
        self.assertNotEqual(lock.read_bytes(), original_lock)
        updated = manifest.read_text(encoding="utf-8")
        self.assertIn("bounded-operating-rule", updated)
        self.assertNotIn("FIRST_INVALID_OUTPUT_CANARY_36ca42", updated)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertTrue(json.loads(status.stdout)["fresh"])

    def test_undeclared_item_artifacts_get_one_visible_correction(self) -> None:
        self.create_item_evidence_files()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment["FAKE_RECONCILE_CORRECTION_MODE"] = (
            "undeclared-item-artifacts-once"
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [item["attempt"] for item in self.read_correction_invocations(record)],
            [1, 2],
        )
        self.assertIn(
            "ctx reconcile: [4/5] proposal rejected before publication "
            "(proposed item artifact is missing a top-level artifact role)",
            result.stderr,
        )
        updated = (self.project / ".ctx" / "context.yaml").read_text(
            encoding="utf-8"
        )
        for path in (
            "tests/researchCoverage.test.ts",
            "tests/mapLayers.test.ts",
            "tests/affordableHousing.test.ts",
        ):
            self.assertIn(f"  - path: {path}\n", updated)
        correction_prompt = str(self.read_correction_invocations(record)[1]["prompt"])
        self.assertIn(
            "subset of the same manifest's top-level `artifacts[].path` set",
            correction_prompt,
        )
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_repeated_undeclared_item_artifacts_fail_visibly_without_writes(
        self,
    ) -> None:
        self.create_item_evidence_files()
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment["FAKE_RECONCILE_CORRECTION_MODE"] = (
            "undeclared-item-artifacts-always"
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            [item["attempt"] for item in self.read_correction_invocations(record)],
            [1, 2],
        )
        self.assertIn(
            "ctx reconcile: [4/5] corrected proposal rejected; no project files changed",
            result.stderr,
        )
        self.assertIn(
            "after one correction attempt; no project files changed",
            result.stderr,
        )
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual(lock.read_bytes(), original_lock)

    def test_second_local_manifest_schema_error_fails_without_writes(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        source_canary = "RECONCILE_SECOND_INVALID_SOURCE_CANARY_15a404"
        transcript_canary = "RECONCILE_SECOND_INVALID_TRANSCRIPT_CANARY_e828d7"
        self.source.write_text(source_canary + "\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment.update(
            {
                "FAKE_RECONCILE_CORRECTION_MODE": "invalid-summary-always",
                "FAKE_RECONCILE_TRANSCRIPT_CANARY": transcript_canary,
            }
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("reconcile.agent-output-invalid", result.stderr)
        self.assertEqual(
            [item["attempt"] for item in self.read_correction_invocations(record)],
            [1, 2],
        )
        combined_output = result.stdout + result.stderr
        self.assertNotIn("CTX_RECONCILE_PROMPT_VERSION=2", combined_output)
        self.assertNotIn("RECONCILE_RESULT_TRANSCRIPT_CANARY_b25344", combined_output)
        self.assertNotIn(source_canary, combined_output)
        self.assertNotIn(transcript_canary, combined_output)
        self.assertNotIn("FIRST_INVALID_OUTPUT_CANARY_36ca42", combined_output)
        self.assertLess(len(result.stdout), 20_000)
        self.assertLess(len(result.stderr), 20_000)
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual(lock.read_bytes(), original_lock)

    def test_valid_update_preserves_adapter_name_in_summary_prose(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        original = manifest.read_text(encoding="utf-8")
        preserved_summary = (
            "Durable prose preserves the `.ctx-retrofit` adapter name as project "
            "context."
        )
        manifest.write_text(
            original.replace(
                "node:\n  id: root\n  name: Reconcile Project\n",
                "node:\n  id: root\n  name: Reconcile Project\n"
                f"  summary: {preserved_summary}\n",
            ),
            encoding="utf-8",
        )
        seal_freshness(self.project)
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment["FAKE_RECONCILE_CORRECTION_MODE"] = (
            "valid-preserve-adapter-prose"
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [item["attempt"] for item in self.read_correction_invocations(record)],
            [1],
        )
        updated = manifest.read_text(encoding="utf-8")
        self.assertIn(preserved_summary, updated)
        self.assertIn("bounded-operating-rule", updated)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_unpaired_surrogates_are_rejected_before_reconcile_publication(
        self,
    ) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        executable_directory, record, base_environment = self.correction_fake_codex()

        for mode in ("surrogate-summary", "surrogate-acknowledgement"):
            with self.subTest(mode=mode):
                record.unlink(missing_ok=True)
                environment = dict(base_environment)
                environment.update(
                    {
                        "PATH": str(executable_directory)
                        + os.pathsep
                        + os.environ.get("PATH", ""),
                        "FAKE_RECONCILE_CORRECTION_MODE": mode,
                    }
                )
                result = self.run_ctx(
                    "reconcile",
                    extra_environment=environment,
                )

                self.assertEqual(
                    result.returncode,
                    1,
                    result.stdout + result.stderr,
                )
                self.assertIn("reconcile.agent-output-invalid", result.stderr)
                self.assertNotIn("internal.error", result.stderr)
                self.assertEqual(
                    [
                        item["attempt"]
                        for item in self.read_correction_invocations(record)
                    ],
                    [1, 2],
                )
                (result.stdout + result.stderr).encode("utf-8")
                self.assertEqual(manifest.read_bytes(), original_manifest)
                self.assertEqual(lock.read_bytes(), original_lock)

        self.assertEqual(_safe_display(chr(0xD800)), "\\ud800")

    def test_second_attempt_cannot_reuse_the_first_attempt_result(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        transcript_canary = "MISSING_SECOND_RESULT_TRANSCRIPT_CANARY_78d206"
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment.update(
            {
                "FAKE_RECONCILE_CORRECTION_MODE": (
                    "invalid-summary-then-missing-result"
                ),
                "FAKE_RECONCILE_TRANSCRIPT_CANARY": transcript_canary,
            }
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("reconcile.agent-output-invalid", result.stderr)
        invocations = self.read_correction_invocations(record)
        self.assertEqual([item["attempt"] for item in invocations], [1, 2])
        self.assertNotEqual(
            invocations[0]["result_path"], invocations[1]["result_path"]
        )
        self.assertNotIn(transcript_canary, result.stdout + result.stderr)
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual(lock.read_bytes(), original_lock)

    def test_policy_graph_provider_and_race_errors_do_not_get_correction_pass(
        self,
    ) -> None:
        executable_directory, record, base_environment = self.correction_fake_codex()
        cases = (
            ("unsafe-path", 3, "reconcile.proposal-path"),
            ("invalid-before-unsafe", 3, "reconcile.proposal-path"),
            ("unsafe-before-invalid", 3, "reconcile.proposal-path"),
            (
                "invalid-with-duplicate-coverage",
                1,
                "reconcile.coverage-duplicate",
            ),
            (
                "invalid-with-generated-diff-reference",
                1,
                "reconcile.agent-output-invalid",
            ),
            (
                "invalid-with-adapter-reference",
                1,
                "reconcile.agent-output-invalid",
            ),
            ("coverage-incomplete", 1, "reconcile.coverage-incomplete"),
            ("graph-invalid", 1, None),
            ("provider-failure", 4, "reconcile.agent-failed"),
            (
                "invalid-summary-with-source-race",
                4,
                "reconcile.project-changed",
            ),
            (
                "invalid-summary-with-manifest-race",
                4,
                "reconcile.project-changed",
            ),
        )
        for mode, expected_exit, expected_error in cases:
            with self.subTest(mode=mode):
                record.unlink(missing_ok=True)
                project = self.base / f"no-correction-{mode}"
                project.mkdir()
                source = project / "app.py"
                source.write_text("VALUE = 1\n", encoding="utf-8")
                initialized = self.run_ctx(
                    "init",
                    str(project),
                    "--id",
                    "reconcile-project",
                    "--name",
                    "Reconcile Project",
                )
                self.assertEqual(
                    initialized.returncode,
                    0,
                    initialized.stdout + initialized.stderr,
                )
                seal_freshness(project)
                manifest = project / ".ctx" / "context.yaml"
                lock = project / ".ctx" / "lock.json"
                original_manifest = manifest.read_bytes()
                original_lock = lock.read_bytes()
                source.write_text("VALUE = 2\n", encoding="utf-8")
                environment = dict(base_environment)
                environment.update(
                    {
                        "PATH": str(executable_directory)
                        + os.pathsep
                        + os.environ.get("PATH", ""),
                        "FAKE_RECONCILE_CORRECTION_MODE": mode,
                        "FAKE_RECONCILE_LIVE_ROOT": str(project.resolve()),
                    }
                )

                result = self.run_ctx(
                    "reconcile",
                    str(project),
                    extra_environment=environment,
                )

                self.assertEqual(
                    result.returncode,
                    expected_exit,
                    result.stdout + result.stderr,
                )
                if expected_error is not None:
                    self.assertIn(expected_error, result.stderr)
                self.assertEqual(
                    [
                        item["attempt"]
                        for item in self.read_correction_invocations(record)
                    ],
                    [1],
                )
                if mode == "invalid-summary-with-manifest-race":
                    self.assertIn(
                        "MANIFEST_RACE_CANARY_1cb282",
                        manifest.read_text(encoding="utf-8"),
                    )
                    self.assertNotIn("bounded-operating-rule", manifest.read_text())
                else:
                    self.assertEqual(manifest.read_bytes(), original_manifest)
                self.assertEqual(lock.read_bytes(), original_lock)

    def test_race_after_correction_is_rejected_without_publication(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        original_manifest = manifest.read_bytes()
        original_lock = lock.read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, record, environment = self.correction_fake_codex()
        environment["FAKE_RECONCILE_CORRECTION_MODE"] = (
            "invalid-summary-then-source-race"
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("reconcile.project-changed", result.stderr)
        self.assertEqual(
            [item["attempt"] for item in self.read_correction_invocations(record)],
            [1, 2],
        )
        self.assertEqual(manifest.read_bytes(), original_manifest)
        self.assertEqual(lock.read_bytes(), original_lock)
        self.assertEqual(
            self.source.read_text(encoding="utf-8"),
            "CHANGED_DURING_REVIEW = True\n",
        )

    def test_acknowledgement_preserves_manifest_and_refreshes_lock(self) -> None:
        before = (self.project / ".ctx" / "context.yaml").read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        directory, environment = self.fake_codex()
        result = self.run_ctx("reconcile", extra_environment=environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 node(s) acknowledged", result.stdout)
        self.assertEqual((self.project / ".ctx" / "context.yaml").read_bytes(), before)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertTrue(json.loads(status.stdout)["fresh"])

    def test_reconcile_reports_stages_on_stderr_and_keeps_stdout_clean(self) -> None:
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, environment = self.fake_codex()

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RECONCILE COMPLETE", result.stdout)
        self.assertNotIn("ctx reconcile:", result.stdout)
        for marker in (
            "ctx reconcile: [1/5] checking context freshness",
            "ctx reconcile: [2/5] inventorying",
            "ctx reconcile: [2/5] prepared bounded read-only snapshot",
            "ctx reconcile: [3/5] starting Codex semantic review",
            "ctx reconcile: [4/5] Codex review finished",
            "ctx reconcile: [5/5] proposal valid",
            "ctx reconcile: [5/5] strict validation passed",
            "ctx reconcile: [5/5] reconciliation published",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, result.stderr)

    def test_reconcile_agent_wait_reports_elapsed_heartbeat(self) -> None:
        messages: list[str] = []
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(0.06)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.addCleanup(
            lambda: process.kill() if process.poll() is None else None
        )

        with mock.patch.object(
            reconciliation,
            "RECONCILE_AGENT_HEARTBEAT_SECONDS",
            0.01,
        ):
            returncode = reconciliation._wait_for_reconcile_agent(
                process,
                progress=messages.append,
                label="[3/5] Codex semantic review",
            )

        self.assertEqual(returncode, 0)
        self.assertTrue(
            any(
                "Codex semantic review still running" in message
                and "elapsed" in message
                and "Ctrl-C to stop safely" in message
                for message in messages
            ),
            messages,
        )

    @unittest.skipIf(os.name == "nt", "requires symlink support")
    def test_dependency_symlink_is_excluded_from_guarded_reconciliation(self) -> None:
        dependency_target = self.base / "shared-node-modules"
        dependency_target.mkdir()
        dependency_link = self.project / "node_modules"
        try:
            dependency_link.symlink_to(dependency_target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        seal_freshness(self.project)
        baseline = self.run_ctx("status", "--check", "--json")
        self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
        baseline_status = json.loads(baseline.stdout)
        self.assertEqual(baseline_status["nodes"][0]["files"], 1)
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, environment = self.fake_codex()
        record = self.base / "dependency-symlink-snapshot.json"
        environment["FAKE_RECONCILE_RECORD"] = str(record)

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        copied = set(json.loads(record.read_text(encoding="utf-8")))
        self.assertNotIn("node_modules", copied)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertTrue(json.loads(status.stdout)["fresh"])

    def test_explicit_acknowledgement_is_two_word_no_agent_path(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        before = manifest.read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        result = self.run_ctx(
            "reconcile",
            "--acknowledge",
            "Reviewed as an implementation-only constant change.",
            extra_environment={"PATH": str(self.base / "no-agent-bin")},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(manifest.read_bytes(), before)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_agent_snapshot_exposes_affected_scope_not_unrelated_sibling_source(self) -> None:
        alpha = self.project / "alpha"
        beta = self.project / "beta"
        alpha.mkdir()
        beta.mkdir()
        alpha_source = alpha / "source.py"
        beta_source = beta / "unrelated.py"
        root_contract = self.project / "root_contract.py"
        alpha_source.write_text("VALUE = 'alpha'\n", encoding="utf-8")
        beta_source.write_text("SIBLING_CANARY = 'private-to-beta'\n", encoding="utf-8")
        (beta / "AGENT.md").write_text(
            "SIBLING_INSTRUCTION_CANARY\n", encoding="utf-8"
        )
        root_contract.write_text("ROOT_CONTRACT = True\n", encoding="utf-8")
        for path, node_id, name in (
            (alpha, "alpha", "Alpha"),
            (beta, "beta", "Beta"),
        ):
            initialized = self.run_ctx(
                "node",
                str(path),
                "--id",
                node_id,
                "--name",
                name,
            )
            self.assertEqual(
                initialized.returncode, 0, initialized.stdout + initialized.stderr
            )
        root_manifest = self.project / ".ctx" / "context.yaml"
        root_manifest.write_text(
            root_manifest.read_text(encoding="utf-8")
            + "artifacts:\n"
            + "  - path: root_contract.py\n"
            + "    role: Root contract inherited by child reviews.\n",
            encoding="utf-8",
        )
        seal_freshness(self.project)
        alpha_source.write_text("VALUE = 'changed'\n", encoding="utf-8")
        _directory, environment = self.fake_codex()
        record = self.base / "reconcile-snapshot.json"
        environment.update(
            {
                "FAKE_RECONCILE_RECORD": str(record),
                "FAKE_RECONCILE_URI": "ctx://reconcile-project/alpha",
            }
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        copied = set(json.loads(record.read_text(encoding="utf-8")))
        self.assertIn("alpha/source.py", copied)
        self.assertIn("root_contract.py", copied)
        self.assertNotIn("beta/unrelated.py", copied)
        self.assertNotIn("beta/AGENT.md", copied)
        self.assertNotIn("beta/.ctx/context.yaml", copied)
        self.assertNotIn("app.py", copied)

    def test_agent_snapshot_includes_bounded_linked_peer_evidence(self) -> None:
        alpha = self.project / "alpha"
        beta = self.project / "beta"
        alpha.mkdir()
        beta.mkdir()
        alpha_source = alpha / "source.py"
        beta_contract = beta / "consumer.py"
        beta_internal = beta / "internal.py"
        alpha_source.write_text("VALUE = 'alpha'\n", encoding="utf-8")
        beta_contract.write_text("CONSUMES_ALPHA = True\n", encoding="utf-8")
        beta_internal.write_text("PRIVATE_BETA = True\n", encoding="utf-8")
        for path, node_id, name in (
            (alpha, "alpha", "Alpha"),
            (beta, "beta", "Beta"),
        ):
            initialized = self.run_ctx(
                "node",
                str(path),
                "--id",
                node_id,
                "--name",
                name,
            )
            self.assertEqual(
                initialized.returncode, 0, initialized.stdout + initialized.stderr
            )
        alpha_manifest = alpha / ".ctx" / "context.yaml"
        alpha_manifest.write_text(
            alpha_manifest.read_text(encoding="utf-8")
            + "links:\n"
            + "  - target: ctx://reconcile-project/beta\n"
            + "    relation: related_to\n",
            encoding="utf-8",
        )
        beta_manifest = beta / ".ctx" / "context.yaml"
        beta_manifest.write_text(
            beta_manifest.read_text(encoding="utf-8")
            + "artifacts:\n"
            + "  - path: consumer.py\n"
            + "    role: Public consumer contract for Alpha behavior.\n",
            encoding="utf-8",
        )
        seal_freshness(self.project)
        alpha_source.write_text("VALUE = 'changed'\n", encoding="utf-8")
        _directory, environment = self.fake_codex()
        record = self.base / "linked-reconcile-snapshot.json"
        environment.update(
            {
                "FAKE_RECONCILE_RECORD": str(record),
                "FAKE_RECONCILE_URI": "ctx://reconcile-project/alpha",
            }
        )

        result = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        copied = set(json.loads(record.read_text(encoding="utf-8")))
        self.assertIn("alpha/source.py", copied)
        self.assertIn("beta/.ctx/context.yaml", copied)
        self.assertIn("beta/consumer.py", copied)
        self.assertNotIn("beta/internal.py", copied)

    def test_update_changes_only_manifest_then_refreshes_lock(self) -> None:
        source_before = self.source.read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        changed_source = self.source.read_bytes()
        _directory, environment = self.fake_codex()
        environment["FAKE_RECONCILE_MODE"] = "update"
        result = self.run_ctx("reconcile", extra_environment=environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 manifest(s) updated", result.stdout)
        manifest = (self.project / ".ctx" / "context.yaml").read_text(encoding="utf-8")
        self.assertIn("Durable purpose updated", manifest)
        self.assertEqual(self.source.read_bytes(), changed_source)
        self.assertNotEqual(source_before, changed_source)
        status = self.run_ctx("status", "--check", "--json")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)

    def test_invalid_graph_proposal_never_changes_live_manifest(self) -> None:
        manifest = self.project / ".ctx" / "context.yaml"
        before_manifest = manifest.read_bytes()
        before_lock = (self.project / ".ctx" / "lock.json").read_bytes()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        _directory, environment = self.fake_codex()
        environment["FAKE_RECONCILE_MODE"] = "graph-invalid"
        result = self.run_ctx("reconcile", extra_environment=environment)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("RECONCILE PROPOSAL REJECTED", result.stdout)
        self.assertIn("no project files changed", result.stdout)
        self.assertNotIn("INVALID reconcile-project", result.stdout)
        self.assertIn(
            "ctx reconcile: [4/5] proposal rejected by strict graph validation; "
            "no project files changed",
            result.stderr,
        )
        self.assertIn(str(manifest), result.stderr)
        self.assertNotIn("/ctx-reconcile-", result.stderr)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual((self.project / ".ctx" / "lock.json").read_bytes(), before_lock)

    def test_doctor_and_reconcile_use_the_same_explicit_override(self) -> None:
        override_directory, environment = self.fake_codex()
        override = (override_directory / "codex").resolve()
        shadow_directory = self.base / "shadow-bin"
        shadow_directory.mkdir()
        shadow = shadow_directory / "codex"
        shadow.write_text("#!/bin/sh\nexit 87\n", encoding="utf-8")
        shadow.chmod(shadow.stat().st_mode | stat.S_IXUSR)
        environment.update(
            {
                "CTX_CODEX": str(override),
                "PATH": str(shadow_directory),
            }
        )

        diagnosed = self.run_ctx("doctor", "--json", extra_environment=environment)

        self.assertEqual(diagnosed.returncode, 0, diagnosed.stdout + diagnosed.stderr)
        diagnosis = json.loads(diagnosed.stdout)
        self.assertEqual(diagnosis["codex"], str(override))
        self.assertEqual(diagnosis["codex_source"], "environment")

        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        reconciled = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(reconciled.returncode, 0, reconciled.stdout + reconciled.stderr)
        self.assertIn("1 node(s) acknowledged", reconciled.stdout)

    def test_doctor_and_reconcile_fail_consistently_for_invalid_override(self) -> None:
        directory, environment = self.fake_codex()
        missing = (self.base / "missing" / "codex").resolve()
        environment.update(
            {
                "CTX_CODEX": str(missing),
                "PATH": str(directory),
            }
        )

        diagnosed = self.run_ctx("doctor", "--json", extra_environment=environment)
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        reconciled = self.run_ctx("reconcile", extra_environment=environment)

        self.assertEqual(diagnosed.returncode, 4, diagnosed.stdout + diagnosed.stderr)
        self.assertEqual(
            json.loads(diagnosed.stdout)["error"]["code"],
            "codex.executable-invalid",
        )
        self.assertEqual(reconciled.returncode, 4, reconciled.stdout + reconciled.stderr)
        self.assertIn("codex.executable-invalid", reconciled.stderr)


if __name__ == "__main__":
    unittest.main()
