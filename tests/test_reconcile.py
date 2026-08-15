from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.freshness import seal_freshness


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
mode = os.environ.get("FAKE_RECONCILE_MODE", "ack")
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
    payload = {{
        "manifests": [],
        "acknowledgements": [{{
            "uri": "ctx://reconcile-project",
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
