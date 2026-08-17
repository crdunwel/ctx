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


DIFF_PATH = ".ctx-retrofit-reconcile-diff.patch"
MAX_DIFF_BYTES = 131_072


class GuardedReconcileDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.ctx_home = self.base / "ctx-home"
        self.home.mkdir()
        self.project = self.base / "project"
        self.project.mkdir()
        self.source = self.project / "app.py"
        self.source.write_text("VALUE = 'before'\n", encoding="utf-8")
        initialized = self.run_ctx(
            "init",
            str(self.project),
            "--id",
            "diff-project",
            "--name",
            "Diff Project",
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
            cwd=self.project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
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

    def commit_all(self, message: str = "baseline") -> None:
        if not (self.project / ".git").exists():
            self.git("init", "-q")
            self.git("config", "user.email", "ctx-tests@example.invalid")
            self.git("config", "user.name", "ctx tests")
        self.git("add", "-A")
        if (self.project / ".env").exists():
            self.git("add", "-f", ".env")
        self.git("commit", "--no-verify", "-q", "-m", message)

    def fake_codex(
        self,
        *,
        record: Path,
        acknowledgement_uri: str = "ctx://diff-project",
        mode: str = "ack",
    ) -> dict[str, str]:
        directory = self.base / "bin"
        directory.mkdir(exist_ok=True)
        executable = directory / "codex"
        script = f'''#!{Path(sys.executable).resolve()}
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
workspace = Path(arguments[arguments.index("-C") + 1])
result = Path(arguments[arguments.index("--output-last-message") + 1])
prompt = sys.stdin.read()
diff_path = workspace / {DIFF_PATH!r}
diff_bytes = diff_path.read_bytes()
Path(os.environ["RECONCILE_DIFF_RECORD"]).write_text(
    json.dumps({{
        "diff": diff_bytes.decode("utf-8", errors="replace"),
        "diff_size": len(diff_bytes),
        "files": sorted(
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        ),
        "prompt": prompt,
    }}, sort_keys=True),
    encoding="utf-8",
)
if os.environ.get("RECONCILE_DIFF_MODE") == "adopt":
    manifest = (workspace / ".ctx" / "context.yaml").read_text(encoding="utf-8")
    manifest += "artifacts:\\n  - path: {DIFF_PATH}\\n    role: Generated adapter evidence.\\n"
    payload = {{
        "manifests": [{{"path": ".ctx/context.yaml", "content": manifest}}],
        "acknowledgements": [],
        "summary": "Tried to adopt generated evidence.",
    }}
else:
    payload = {{
        "manifests": [],
        "acknowledgements": [{{
            "uri": os.environ["RECONCILE_DIFF_ACK_URI"],
            "reason": "Implementation-only source change with no durable semantic impact.",
        }}],
        "summary": "Reviewed bounded change evidence.",
    }}
result.write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")
'''
        executable.write_text(script, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return {
            "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
            "RECONCILE_DIFF_RECORD": str(record),
            "RECONCILE_DIFF_ACK_URI": acknowledgement_uri,
            "RECONCILE_DIFF_MODE": mode,
        }

    def read_record(self, path: Path) -> dict[str, object]:
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def test_diff_is_limited_to_affected_scope_and_redacts_deleted_bodies(self) -> None:
        alpha = self.project / "alpha"
        beta = self.project / "beta"
        alpha.mkdir()
        beta.mkdir()
        alpha_source = alpha / "source.py"
        beta_source = beta / "unrelated.py"
        alpha_source.write_text("ALPHA_OLD_CANARY = True\n", encoding="utf-8")
        beta_source.write_text("BETA_OLD_CANARY = True\n", encoding="utf-8")
        for path, node_id in ((alpha, "alpha"), (beta, "beta")):
            initialized = self.run_ctx(
                "node", str(path), "--id", node_id, "--name", node_id.title()
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
        beta_manifest = beta / ".ctx" / "context.yaml"
        beta_manifest.write_text(
            beta_manifest.read_text(encoding="utf-8")
            + "tracking:\n  exclude:\n    - unrelated.py\n",
            encoding="utf-8",
        )
        seal_freshness(self.project)
        self.commit_all()

        alpha_source.write_text("ALPHA_NEW_VALUE = True\n", encoding="utf-8")
        beta_source.write_text("BETA_UNRELATED_SECRET = True\n", encoding="utf-8")
        record_path = self.base / "affected.json"
        result = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(
                record=record_path,
                acknowledgement_uri="ctx://diff-project/alpha",
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.read_record(record_path)
        diff = str(record["diff"])
        self.assertIn("alpha/source.py", diff)
        self.assertIn("+ALPHA_NEW_VALUE = True", diff)
        self.assertNotIn("ALPHA_OLD_CANARY", diff)
        self.assertIn("-[deleted line content redacted by ctx]", diff)
        self.assertNotIn("beta/unrelated.py", diff)
        self.assertNotIn("BETA_UNRELATED_SECRET", diff)
        self.assertIn("supplemental change evidence", str(record["prompt"]))
        self.assertIn(DIFF_PATH, record["files"])

    def test_diff_combines_staged_and_unstaged_worktree_changes(self) -> None:
        worker = self.project / "worker.py"
        worker.write_text("WORKER_OLD_CANARY = True\n", encoding="utf-8")
        seal_freshness(self.project)
        self.commit_all()
        self.source.write_text("STAGED_VALUE = True\n", encoding="utf-8")
        self.git("add", "app.py")
        worker.write_text("UNSTAGED_VALUE = True\n", encoding="utf-8")
        untracked = self.project / "new_source.py"
        untracked.write_text("UNTRACKED_VALUE = True\n", encoding="utf-8")
        record_path = self.base / "mixed.json"

        result = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(record=record_path),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        diff = str(self.read_record(record_path)["diff"])
        self.assertIn("+STAGED_VALUE = True", diff)
        self.assertIn("+UNSTAGED_VALUE = True", diff)
        self.assertNotIn("WORKER_OLD_CANARY", diff)
        self.assertIn("Git HEAD to the current working tree", diff)
        self.assertIn(
            'Untracked current-source additions; inspect these snapshot files: ["new_source.py"]',
            diff,
        )

    def test_secret_named_paths_are_not_exposed_by_diff(self) -> None:
        secret = self.project / ".env"
        secret.write_text("TOKEN=OLD_SECRET\n", encoding="utf-8")
        seal_freshness(self.project)
        self.commit_all()
        secret.write_text("TOKEN=NEW_SECRET_CANARY\n", encoding="utf-8")
        self.source.write_text("SAFE_CHANGE = True\n", encoding="utf-8")
        record_path = self.base / "secret.json"

        result = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(record=record_path),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        diff = str(self.read_record(record_path)["diff"])
        self.assertIn("+SAFE_CHANGE = True", diff)
        self.assertNotIn(".env", diff)
        self.assertNotIn("NEW_SECRET_CANARY", diff)
        self.assertNotIn("OLD_SECRET", diff)

    def test_large_diff_is_hard_bounded_and_marked_truncated(self) -> None:
        large = self.project / "large.py"
        large.write_text("OLD = True\n", encoding="utf-8")
        seal_freshness(self.project)
        self.commit_all()
        large.write_text(
            "".join(f"ADDED_{index:05d} = 'bounded evidence line'\n" for index in range(12_000)),
            encoding="utf-8",
        )
        record_path = self.base / "large.json"

        result = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(record=record_path),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.read_record(record_path)
        self.assertLessEqual(int(record["diff_size"]), MAX_DIFF_BYTES)
        diff = str(record["diff"])
        self.assertIn("# Status: truncated", diff)
        self.assertIn("hard byte limit", diff)
        self.assertNotIn("ADDED_11999", diff)

    def test_no_git_and_clean_head_have_explicit_fallback_metadata(self) -> None:
        self.source.write_text("NO_GIT_CHANGE = True\n", encoding="utf-8")
        no_git_record = self.base / "no-git.json"
        no_git = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(record=no_git_record),
        )
        self.assertEqual(no_git.returncode, 0, no_git.stdout + no_git.stderr)
        no_git_diff = str(self.read_record(no_git_record)["diff"])
        self.assertIn("# Status: unavailable", no_git_diff)
        self.assertIn("inspect current source directly", no_git_diff)

        seal_freshness(self.project)
        self.commit_all()
        self.source.write_text("COMMITTED_STALE_CHANGE = True\n", encoding="utf-8")
        self.commit_all("source without refreshed lock")
        clean_record = self.base / "clean-head.json"
        clean = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(record=clean_record),
        )
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        clean_diff = str(self.read_record(clean_record)["diff"])
        self.assertIn("# Status: clean", clean_diff)
        self.assertIn("No eligible uncommitted Git changes", clean_diff)

    def test_manifest_cannot_adopt_generated_diff_file(self) -> None:
        self.commit_all()
        self.source.write_text("VALUE = 'changed'\n", encoding="utf-8")
        manifest = self.project / ".ctx" / "context.yaml"
        lock = self.project / ".ctx" / "lock.json"
        before_manifest = manifest.read_bytes()
        before_lock = lock.read_bytes()
        record_path = self.base / "adopt.json"

        result = self.run_ctx(
            "reconcile",
            extra_environment=self.fake_codex(
                record=record_path,
                mode="adopt",
            ),
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("generated reconciliation diff evidence", result.stderr)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(lock.read_bytes(), before_lock)
        self.assertFalse((self.project / DIFF_PATH).exists())


if __name__ == "__main__":
    unittest.main()
