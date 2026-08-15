from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx import retrofit_agent
from ctx.diagnostics import CtxError


EXPECTED_CODEX_HOOKS = {
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


class RetrofitRunTests(unittest.TestCase):
    """Black-box coverage for the agent-assisted one-command retrofit."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.home = self.base / "home"
        self.home.mkdir()

    def run_ctx(
        self,
        *arguments: str,
        cwd: Path | None = None,
        environment_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CTX_HOME"] = str(self.ctx_home)
        environment["HOME"] = str(self.home)
        if environment_overrides:
            environment.update(environment_overrides)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=cwd or self.base,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def install_fake_codex(self) -> tuple[Path, Path]:
        """Install a read-only stand-in that emits a structured proposal."""
        executable_directory = self.base / "fake-bin"
        executable_directory.mkdir(exist_ok=True)
        executable = executable_directory / "codex"
        record = self.base / "codex-invocation.json"
        script = '''#!__PYTHON__
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
schema = json.loads(schema_path.read_text(encoding="utf-8"))
live_root = Path(os.environ["FAKE_CODEX_LIVE_ROOT"])


def snapshot(root: Path) -> list[list[object]]:
    records: list[list[object]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            records.append([relative, "symlink", os.readlink(path)])
        elif stat.S_ISREG(metadata.st_mode):
            records.append(
                [relative, "file", hashlib.sha256(path.read_bytes()).hexdigest()]
            )
        elif stat.S_ISDIR(metadata.st_mode):
            records.append([relative, "directory"])
        else:
            records.append([relative, "special"])
    return records


def text_contents(root: Path) -> dict[str, str]:
    contents: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_file() and not path.is_symlink():
            contents[path.relative_to(root).as_posix()] = path.read_bytes().decode(
                "utf-8", errors="replace"
            )
    return contents


snapshot_before = snapshot(workspace)
live_before = snapshot(live_root)


def invocation_record() -> dict[str, object]:
    return {
        "argv": arguments,
        "cwd": os.getcwd(),
        "stdin": prompt,
        "schema": schema,
        "schema_path": str(schema_path),
        "result_path": str(result_path),
        "snapshot_before": snapshot_before,
        "snapshot_after": snapshot(workspace),
        "snapshot_contents": text_contents(workspace),
        "live_before": live_before,
        "live_after": snapshot(live_root),
    }

root_manifest = """version: 1
project:
  id: retrofit-fixture
  name: Retrofit Fixture
  aliases: []
node:
  id: root
  name: Retrofit Fixture
"""
nested_alpha = """version: 1
node:
  id: shared
  name: Alpha
"""
nested_beta = """version: 1
node:
  id: shared
  name: Beta
"""

mode = os.environ.get("FAKE_CODEX_MODE", "valid")
if mode == "fail":
    Path(os.environ["FAKE_CODEX_RECORD"]).write_text(
        json.dumps(invocation_record(), ensure_ascii=True, sort_keys=True)
        + "\\n",
        encoding="utf-8",
    )
    raise SystemExit(int(os.environ.get("FAKE_CODEX_EXIT", "17")))

if mode == "invalid-path":
    proposal = {
        "manifests": [{"path": "app.py", "content": root_manifest}],
        "summary": "This unsafe source-file proposal must be rejected.",
    }
elif mode == "graph-invalid":
    proposal = {
        "manifests": [
            {"path": ".ctx/context.yaml", "content": root_manifest},
            {"path": "alpha/.ctx/context.yaml", "content": nested_alpha},
            {"path": "beta/.ctx/context.yaml", "content": nested_beta},
        ],
        "summary": "The sibling node identities intentionally collide.",
    }
elif mode == "nested-only":
    proposal = {
        "manifests": [
            {"path": "feature/.ctx/context.yaml", "content": nested_alpha},
        ],
        "summary": "Preserved the existing root and proposed one missing node.",
    }
else:
    proposal = {
        "manifests": [
            {"path": ".ctx/context.yaml", "content": root_manifest},
        ],
        "summary": "Proposed one evidence-backed project root.",
    }

result_path.write_text(
    json.dumps(proposal, ensure_ascii=True, sort_keys=True) + "\\n",
    encoding="utf-8",
)
Path(os.environ["FAKE_CODEX_RECORD"]).write_text(
    json.dumps(invocation_record(), ensure_ascii=True, sort_keys=True)
    + "\\n",
    encoding="utf-8",
)
'''.replace("__PYTHON__", str(Path(sys.executable).resolve()))
        executable.write_text(script, encoding="utf-8")
        executable.chmod(
            executable.stat().st_mode
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
        return executable_directory, record

    def fake_environment(
        self,
        executable_directory: Path,
        record: Path,
        project: Path,
        *,
        mode: str = "valid",
    ) -> dict[str, str]:
        return {
            "PATH": str(executable_directory) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CODEX_RECORD": str(record),
            "FAKE_CODEX_MODE": mode,
            "FAKE_CODEX_LIVE_ROOT": str(project.resolve()),
        }

    def read_invocation(self, record: Path) -> dict[str, object]:
        return json.loads(record.read_text(encoding="utf-8"))

    def assert_workspace_invocation(
        self, invocation: dict[str, object], project: Path
    ) -> Path:
        arguments = invocation["argv"]
        self.assertIsInstance(arguments, list)
        assert isinstance(arguments, list)
        self.assertEqual(arguments[0], "exec")
        self.assertEqual(arguments[-1], "-")
        self.assertIn("-C", arguments)
        snapshot_root = Path(str(arguments[arguments.index("-C") + 1]))
        original_root = project.resolve()
        self.assertNotEqual(snapshot_root, original_root)
        self.assertFalse(snapshot_root.is_relative_to(original_root))
        self.assertEqual(Path(str(invocation["cwd"])), snapshot_root)
        self.assertNotIn("--sandbox", arguments)
        self.assertIn("--skip-git-repo-check", arguments)
        self.assertIn("--ephemeral", arguments)
        self.assertIn("--ignore-user-config", arguments)
        self.assertIn("--ignore-rules", arguments)
        self.assertIn("--strict-config", arguments)
        for index, value in enumerate(arguments):
            if value == "-c":
                self.assertLess(index + 1, len(arguments))
                self.assertNotEqual(arguments[index + 1], "-c")
                self.assertIn("=", str(arguments[index + 1]))
        self.assertIn('approval_policy="never"', arguments)
        sqlite_values = [
            value
            for value in arguments
            if isinstance(value, str) and value.startswith("sqlite_home=")
        ]
        self.assertEqual(len(sqlite_values), 1)
        sqlite_home = Path(json.loads(sqlite_values[0].split("=", 1)[1]))
        self.assertFalse(sqlite_home.is_relative_to(original_root))
        self.assertFalse(sqlite_home.is_relative_to(snapshot_root))
        self.assertIn('default_permissions="ctx-retrofit"', arguments)
        self.assertIn(
            'permissions.ctx-retrofit.description="Filtered read-only ctx retrofit"',
            arguments,
        )
        self.assertIn(
            'permissions.ctx-retrofit.filesystem={ ":minimal" = "read", '
            '":workspace_roots" = { "." = "read" } }',
            arguments,
        )
        self.assertIn("permissions.ctx-retrofit.network.enabled=false", arguments)
        self.assertIn('project_root_markers=[".ctx-retrofit-root"]', arguments)
        self.assertIn('shell_environment_policy.inherit="core"', arguments)
        self.assertIn(
            "shell_environment_policy.ignore_default_excludes=false", arguments
        )
        self.assertIn('web_search="disabled"', arguments)
        self.assertIn("agents.enabled=false", arguments)
        self.assertIn("--disable", arguments)
        self.assertEqual(arguments[arguments.index("--disable") + 1], "hooks")
        self.assertIn("--output-schema", arguments)
        self.assertIn("--output-last-message", arguments)
        self.assertNotIn("workspace-write", arguments)

        schema_path = Path(str(invocation["schema_path"]))
        result_path = Path(str(invocation["result_path"]))
        self.assertFalse(schema_path.is_relative_to(original_root))
        self.assertFalse(result_path.is_relative_to(original_root))
        self.assertFalse(schema_path.is_relative_to(snapshot_root))
        self.assertFalse(result_path.is_relative_to(snapshot_root))
        prompt = invocation["stdin"]
        self.assertIsInstance(prompt, str)
        assert isinstance(prompt, str)
        normalized_prompt = " ".join(prompt.split())
        self.assertIn(str(snapshot_root), prompt)
        self.assertNotIn(str(original_root), prompt)
        for evidence_lens in (
            "core implementation",
            "contract or schema",
            "integration seam",
            "representative test or fixture",
            "version, migration, or configuration anchor",
        ):
            self.assertIn(evidence_lens, prompt)
        self.assertIn("evidence lenses, not required slots", prompt)
        for cross_scope_requirement in (
            "smallest evidenced end-to-end chain",
            "producer or input",
            "persistence or public API boundary",
            "user-facing or operator consumer",
            "representative cross-layer test or fixture",
            "precedence or fallback path",
            "unknown, partial, missing, or inconclusive states",
            "enforcement boundary",
            "representative negative test",
            "project root and every proposed non-leaf node",
            "sibling and grandchild content dormant",
        ):
            self.assertIn(cross_scope_requirement, normalized_prompt)
        self.assertIn(
            "Never create a node, item, file, test, fixture", normalized_prompt
        )
        self.assertIn("Every item artifact path", normalized_prompt)
        self.assertIn("selective subset", prompt)
        self.assertIn(
            "Never edit source to add a ctx backlink, comment", normalized_prompt
        )
        self.assertIn(
            "Do not start, switch, or complete a run-scoped reconciliation",
            normalized_prompt,
        )
        self.assertNotIn("ctx begin", normalized_prompt)
        self.assertNotIn("ctx reconcile inspect", normalized_prompt)
        self.assertNotIn("ctx reconcile acknowledge", normalized_prompt)
        self.assertNotIn("ctx reconcile complete", normalized_prompt)
        self.assertIn("Do not attempt to create, edit, register", normalized_prompt)
        self.assertNotIn(str(original_root), " ".join(str(value) for value in arguments))
        schema = invocation["schema"]
        self.assertIsInstance(schema, dict)
        assert isinstance(schema, dict)
        self.assertEqual(schema["required"], ["manifests", "summary"])
        self.assertEqual(schema["additionalProperties"], False)
        return snapshot_root

    def assert_agent_snapshot_was_read_only(
        self, invocation: dict[str, object]
    ) -> None:
        self.assertEqual(invocation["snapshot_before"], invocation["snapshot_after"])

    def assert_live_target_unchanged_during_agent(
        self, invocation: dict[str, object]
    ) -> None:
        self.assertEqual(invocation["live_before"], invocation["live_after"])

    def assert_agent_observed_no_ctx(self, invocation: dict[str, object]) -> None:
        paths = {
            record[0]
            for record in invocation["snapshot_after"]
            if isinstance(record, list) and record
        }
        self.assertFalse(any(path == ".ctx" or path.startswith(".ctx/") for path in paths))

    def assert_canonical_project_hooks(self, project: Path) -> bytes:
        hooks_path = project / ".codex" / "hooks.json"
        self.assertTrue(hooks_path.is_file(), f"missing project hooks: {hooks_path}")
        raw = hooks_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(json.loads(raw), EXPECTED_CODEX_HOOKS)
        self.assertEqual(
            raw,
            (
                json.dumps(
                    EXPECTED_CODEX_HOOKS,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8"),
        )
        return raw

    def test_default_cwd_runs_codex_and_validates_result(self) -> None:
        project = self.base / "default-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            cwd=project,
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = self.read_invocation(record)
        self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assert_agent_observed_no_ctx(invocation)
        self.assertTrue((project / ".ctx" / "context.yaml").is_file())
        self.assertTrue((project / ".ctx" / "lock.json").is_file())
        self.assert_canonical_project_hooks(project)
        self.assertIn("hooks created", result.stdout)
        registry = json.loads((self.ctx_home / "registry.json").read_text(encoding="utf-8"))
        self.assertEqual(
            Path(registry["projects"]["retrofit-fixture"]["root"]),
            project.resolve(),
        )
        second = self.run_ctx(
            "retrofit",
            cwd=project,
            environment_overrides={"PATH": str(self.base / "no-agent-bin")},
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("RETROFIT UNCHANGED", second.stdout)
        self.assertIn("no agent needed", second.stdout)

    def test_fresh_existing_project_installs_missing_hooks_idempotently(self) -> None:
        project = self.base / "fresh-existing-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        initial = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )
        self.assertEqual(initial.returncode, 0, initial.stdout + initial.stderr)
        hooks_path = project / ".codex" / "hooks.json"
        self.assert_canonical_project_hooks(project)
        hooks_path.unlink()
        hooks_path.parent.rmdir()
        record.unlink()

        installed = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides={"PATH": str(self.base / "no-agent-bin")},
        )

        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertIn("RETROFIT UNCHANGED", installed.stdout)
        self.assertIn("hooks created", installed.stdout)
        self.assertFalse(record.exists(), "a fresh project must not restart the agent")
        before = self.assert_canonical_project_hooks(project)

        repeated = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides={"PATH": str(self.base / "no-agent-bin")},
        )

        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("RETROFIT UNCHANGED", repeated.stdout)
        self.assertIn("hooks unchanged", repeated.stdout)
        self.assertEqual(hooks_path.read_bytes(), before)
        self.assertFalse(record.exists(), "an idempotent retrofit must not restart the agent")

    def test_no_hooks_opt_out_completes_retrofit_without_codex_integration(self) -> None:
        project = self.base / "agent-neutral-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            "--no-hooks",
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RETROFIT COMPLETE", result.stdout)
        self.assertIn("hooks skipped", result.stdout)
        self.assertTrue((project / ".ctx" / "context.yaml").is_file())
        self.assertTrue((project / ".ctx" / "lock.json").is_file())
        self.assertFalse((project / ".codex").exists())
        registry = json.loads(
            (self.ctx_home / "registry.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            Path(registry["projects"]["retrofit-fixture"]["root"]),
            project.resolve(),
        )

    def test_hook_conflict_rolls_back_new_context_and_preserves_existing_hooks(self) -> None:
        project = self.base / "hook-conflict-project"
        project.mkdir()
        source = project / "app.py"
        source.write_text("SOURCE_CANARY\n", encoding="utf-8")
        hooks_path = project / ".codex" / "hooks.json"
        hooks_path.parent.mkdir()
        original_hooks = b'{"hooks":{"Existing":[]}}\n'
        hooks_path.write_bytes(original_hooks)
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("integration.hooks-conflict", result.stderr)
        self.assertEqual(hooks_path.read_bytes(), original_hooks)
        self.assertEqual(source.read_text(encoding="utf-8"), "SOURCE_CANARY\n")
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse((self.ctx_home / "registry.json").exists())

    def test_unsafe_codex_directory_rolls_back_context_without_following_it(self) -> None:
        project = self.base / "unsafe-codex-project"
        project.mkdir()
        source = project / "app.py"
        source.write_text("SOURCE_CANARY\n", encoding="utf-8")
        outside = self.base / "outside-codex"
        outside.mkdir()
        marker = outside / "marker.txt"
        marker.write_text("OUTSIDE_CANARY\n", encoding="utf-8")
        codex_path = project / ".codex"
        codex_path.symlink_to(outside, target_is_directory=True)
        original_target = os.readlink(codex_path)
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("integration.codex-directory-symlink", result.stderr)
        self.assertTrue(codex_path.is_symlink())
        self.assertEqual(os.readlink(codex_path), original_target)
        self.assertEqual(marker.read_text(encoding="utf-8"), "OUTSIDE_CANARY\n")
        self.assertFalse((outside / "hooks.json").exists())
        self.assertEqual(source.read_text(encoding="utf-8"), "SOURCE_CANARY\n")
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse((self.ctx_home / "registry.json").exists())

    def test_explicit_codex_override_wins_over_path(self) -> None:
        project = self.base / "override-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        override = (executable_directory / "codex").resolve()
        shadow_directory = self.base / "shadow-bin"
        shadow_directory.mkdir()
        shadow = shadow_directory / "codex"
        shadow.write_text("#!/bin/sh\nexit 87\n", encoding="utf-8")
        shadow.chmod(shadow.stat().st_mode | stat.S_IXUSR)
        environment = self.fake_environment(executable_directory, record, project)
        environment.update(
            {
                "CTX_CODEX": str(override),
                "PATH": str(shadow_directory),
            }
        )

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=environment,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(record.is_file())
        self.assert_workspace_invocation(self.read_invocation(record), project)

    def test_registry_collision_rolls_back_new_manifest_and_lock(self) -> None:
        existing = self.base / "existing"
        existing.mkdir()
        initialized = self.run_ctx(
            "init",
            str(existing),
            "--id",
            "retrofit-fixture",
            "--name",
            "Existing",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        registered = self.run_ctx("register", str(existing))
        self.assertEqual(registered.returncode, 0, registered.stderr)

        project = self.base / "collision-target"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("registry.project-conflict", result.stderr)
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse(
            (project / ".codex").exists(),
            "a hook directory created by a failed retrofit must be rolled back",
        )
        registry = json.loads((self.ctx_home / "registry.json").read_text(encoding="utf-8"))
        self.assertEqual(
            Path(registry["projects"]["retrofit-fixture"]["root"]),
            existing.resolve(),
        )

    def test_agent_snapshot_excludes_secret_ignored_generated_and_vendor_files(
        self,
    ) -> None:
        project = self.base / "filtered-project"
        project.mkdir()
        evidence = {
            "app.py": "VISIBLE_SOURCE_EVIDENCE\n",
            ".env": "ENV_SECRET_CANARY_8da2f5\n",
            "ignored-evidence.txt": "IGNORED_CANARY_17c94b\n",
            "client.generated.js": "GENERATED_CANARY_c7e113\n",
            ".codex/config.toml": "CODEX_CONFIG_CANARY_129af0\n",
            "src/example.egg-info/PKG-INFO": "PACKAGING_CANARY_5f2c11\n",
            "vendor/third-party-canary.txt": "VENDOR_CANARY_38ec04\n",
            "outputs/generated-report.txt": "OUTPUT_CANARY_a90a65\n",
            "tmp/session-data.json": "TEMP_CANARY_b3587c\n",
        }
        (project / ".gitignore").write_text(
            "ignored-evidence.txt\n",
            encoding="utf-8",
        )
        for relative, content in evidence.items():
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory,
                record,
                project,
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = self.read_invocation(record)
        snapshot_root = self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assertFalse(snapshot_root.exists(), "the temporary snapshot must be removed")

        snapshot_records = invocation["snapshot_before"]
        self.assertIsInstance(snapshot_records, list)
        assert isinstance(snapshot_records, list)
        snapshot_paths = {
            item[0]
            for item in snapshot_records
            if isinstance(item, list) and item
        }
        self.assertIn("app.py", snapshot_paths)
        self.assertIn(".ctx-retrofit-root", snapshot_paths)
        for excluded in (
            ".env",
            "ignored-evidence.txt",
            "client.generated.js",
            ".codex",
            ".codex/config.toml",
            "src/example.egg-info",
            "src/example.egg-info/PKG-INFO",
            "vendor",
            "vendor/third-party-canary.txt",
            "outputs",
            "outputs/generated-report.txt",
            "tmp",
            "tmp/session-data.json",
        ):
            self.assertNotIn(excluded, snapshot_paths)

        snapshot_contents = invocation["snapshot_contents"]
        self.assertIsInstance(snapshot_contents, dict)
        assert isinstance(snapshot_contents, dict)
        self.assertEqual(snapshot_contents["app.py"], evidence["app.py"])
        copied_text = "\n".join(str(value) for value in snapshot_contents.values())
        prompt = invocation["stdin"]
        self.assertIsInstance(prompt, str)
        assert isinstance(prompt, str)
        for relative, canary in evidence.items():
            if relative == "app.py":
                continue
            self.assertNotIn(canary.strip(), copied_text)
            self.assertNotIn(canary.strip(), prompt)
        for excluded_path in (
            "ignored-evidence.txt",
            "client.generated.js",
            "vendor/third-party-canary.txt",
        ):
            self.assertNotIn(excluded_path, prompt)

        live_records = invocation["live_before"]
        self.assertIsInstance(live_records, list)
        assert isinstance(live_records, list)
        live_paths = {
            item[0]
            for item in live_records
            if isinstance(item, list) and item
        }
        self.assertTrue(set(evidence).issubset(live_paths))
        self.assertFalse(any(path.startswith(".ctx") for path in live_paths))
        self.assertTrue((project / ".ctx" / "context.yaml").is_file())
        for relative, content in evidence.items():
            self.assertEqual((project / relative).read_text(encoding="utf-8"), content)

    def test_dry_run_saves_and_applies_the_exact_proposal_without_second_agent_run(self) -> None:
        project = self.base / "dry-run-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        result = self.run_ctx(
            "retrofit",
            str(project),
            "--dry-run",
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RETROFIT DRY RUN", result.stdout)
        self.assertIn("Review exact proposal: ctx retrofit --show-plan ", result.stdout)
        self.assertIn("Apply exact proposal: ctx retrofit --apply ", result.stdout)
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse((project / ".codex").exists())
        self.assertFalse((self.ctx_home / "registry.json").exists())
        plan_id = result.stdout.split("ctx retrofit --apply ", 1)[1].split()[0]
        plan_path = self.ctx_home / "retrofit-plans" / f"{plan_id}.json"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(plan["schema"], "ctx-retrofit-plan/v1")
        self.assertEqual(plan["root"], str(project.resolve()))
        planned_content = plan["manifests"][0]["content"]

        record.unlink()
        shown = self.run_ctx(
            "retrofit",
            "--show-plan",
            plan_id,
            environment_overrides={"PATH": os.pathsep.join(("/usr/bin", "/bin"))},
        )
        self.assertEqual(shown.returncode, 0, shown.stdout + shown.stderr)
        shown_plan = json.loads(shown.stdout)
        self.assertEqual(shown_plan["plan_id"], plan_id)
        self.assertEqual(shown_plan["manifests"][0]["content"], planned_content)
        self.assertFalse(record.exists(), "showing a saved plan must not start Codex")

        applied = self.run_ctx(
            "retrofit",
            "--apply",
            plan_id,
            environment_overrides={"PATH": os.pathsep.join(("/usr/bin", "/bin"))},
        )
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn("created from saved plan", applied.stdout)
        self.assertFalse(record.exists(), "applying a saved plan must not start Codex")
        self.assertEqual(
            (project / ".ctx" / "context.yaml").read_text(encoding="utf-8"),
            planned_content,
        )
        self.assertTrue((project / ".ctx" / "lock.json").is_file())
        self.assertTrue((self.ctx_home / "registry.json").is_file())
        self.assert_canonical_project_hooks(project)
        self.assertIn("hooks created", applied.stdout)

    def test_dry_run_no_hooks_retains_opt_out_in_apply_command(self) -> None:
        project = self.base / "dry-run-no-hooks-project"
        project.mkdir()
        (project / "app.py").write_text("print('legacy')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            "--dry-run",
            "--no-hooks",
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        apply_line = next(
            line
            for line in result.stdout.splitlines()
            if line.startswith("Apply exact proposal: ctx retrofit --apply ")
        )
        self.assertIn("--no-hooks", apply_line.split())
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse((project / ".codex").exists())

    def test_saved_plan_rejects_changed_project_evidence(self) -> None:
        project = self.base / "stale-plan-project"
        project.mkdir()
        source = project / "app.py"
        source.write_text("print('before')\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        dry_run = self.run_ctx(
            "retrofit",
            str(project),
            "--dry-run",
            environment_overrides=self.fake_environment(
                executable_directory, record, project
            ),
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stdout + dry_run.stderr)
        plan_id = dry_run.stdout.split("ctx retrofit --apply ", 1)[1].split()[0]
        source.write_text("print('after')\n", encoding="utf-8")
        record.unlink()

        applied = self.run_ctx(
            "retrofit",
            "--apply",
            plan_id,
            environment_overrides={"PATH": os.pathsep.join(("/usr/bin", "/bin"))},
        )
        self.assertEqual(applied.returncode, 1, applied.stdout + applied.stderr)
        self.assertIn("retrofit.plan-stale", applied.stderr)
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse(record.exists())

    def test_explicit_non_git_path_uses_safe_codex_flags_and_prompt_stdin(self) -> None:
        project = self.base / "explicit-project"
        project.mkdir()
        (project / "main.go").write_text("package main\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()
        environment = self.fake_environment(executable_directory, record, project)
        expected_prompt = self.run_ctx(
            "retrofit",
            "--prompt",
            project.name,
            environment_overrides=environment,
        )
        compatibility_prompt = self.run_ctx(
            "retrofit",
            "prompt",
            project.name,
            environment_overrides=environment,
        )
        self.assertEqual(
            expected_prompt.returncode,
            0,
            expected_prompt.stdout + expected_prompt.stderr,
        )
        self.assertEqual(
            compatibility_prompt.returncode,
            0,
            compatibility_prompt.stdout + compatibility_prompt.stderr,
        )
        self.assertEqual(compatibility_prompt.stdout, expected_prompt.stdout)
        self.assertFalse(record.exists(), "prompt generation must not invoke Codex")
        self.assertFalse(
            (project / ".codex").exists(),
            "prompt generation must not install project hooks",
        )

        result = self.run_ctx(
            "retrofit",
            project.name,
            environment_overrides=environment,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = self.read_invocation(record)
        snapshot_root = self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assert_agent_observed_no_ctx(invocation)
        arguments = invocation["argv"]
        prompt = invocation["stdin"]
        self.assertIsInstance(arguments, list)
        self.assertIsInstance(prompt, str)
        assert isinstance(arguments, list)
        assert isinstance(prompt, str)
        normalized_prompt = prompt.replace(str(snapshot_root), str(project.resolve()))
        self.assertTrue(normalized_prompt.startswith(expected_prompt.stdout))
        self.assertIn("## Automated read-only handoff", prompt)
        self.assertNotIn("CTX_RETROFIT_PROMPT_VERSION=1", " ".join(arguments))
        self.assertFalse((project / ".git").exists())

    def test_invalid_codex_override_fails_as_an_operational_error(self) -> None:
        project = self.base / "missing-agent"
        project.mkdir()
        empty_path = self.base / "empty-path"
        empty_path.mkdir()
        missing = (self.base / "missing" / "codex").resolve()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides={
                "CTX_CODEX": str(missing),
                "PATH": str(empty_path),
            },
        )

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("codex.executable-invalid", result.stderr)
        self.assertFalse((project / ".ctx").exists())

    def test_agent_failure_is_reported_and_skips_validation(self) -> None:
        project = self.base / "failed-agent"
        project.mkdir()
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides={
                **self.fake_environment(
                    executable_directory, record, project, mode="fail"
                ),
                "FAKE_CODEX_EXIT": "23",
            },
        )

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("retrofit.agent-failed", result.stderr)
        self.assertTrue(record.is_file())
        invocation = self.read_invocation(record)
        self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assert_agent_observed_no_ctx(invocation)
        self.assertFalse((project / ".ctx").exists())

    def test_invalid_proposal_is_never_applied(self) -> None:
        project = self.base / "invalid-proposal"
        project.mkdir()
        source = project / "app.py"
        source.write_text("SOURCE_CANARY\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project, mode="invalid-path"
            ),
        )

        self.assertTrue(record.is_file())
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("retrofit.proposal-path", result.stderr)
        invocation = self.read_invocation(record)
        self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assert_agent_observed_no_ctx(invocation)
        self.assertEqual(source.read_text(encoding="utf-8"), "SOURCE_CANARY\n")
        self.assertFalse((project / ".ctx").exists())

    def test_graph_invalid_proposals_are_rolled_back_after_strict_validation(self) -> None:
        project = self.base / "strict-validation"
        (project / "alpha").mkdir(parents=True)
        (project / "beta").mkdir()
        (project / "app.py").write_text("SOURCE_CANARY\n", encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project, mode="graph-invalid"
            ),
        )

        self.assertTrue(record.is_file())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("node.uri-collision", result.stderr)
        invocation = self.read_invocation(record)
        self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assert_agent_observed_no_ctx(invocation)
        self.assertFalse((project / ".ctx").exists())
        self.assertFalse((project / "alpha" / ".ctx").exists())
        self.assertFalse((project / "beta" / ".ctx").exists())
        self.assertEqual(
            (project / "app.py").read_text(encoding="utf-8"),
            "SOURCE_CANARY\n",
        )

    def test_existing_manifest_is_preserved_while_missing_node_is_applied(self) -> None:
        project = self.base / "existing-root"
        root_manifest = project / ".ctx" / "context.yaml"
        root_manifest.parent.mkdir(parents=True)
        (project / "feature").mkdir()
        original = (
            "version: 1\n"
            "project:\n"
            "  id: existing-project\n"
            "  name: Existing Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Existing Project\n"
        )
        root_manifest.write_text(original, encoding="utf-8")
        executable_directory, record = self.install_fake_codex()

        result = self.run_ctx(
            "retrofit",
            str(project),
            environment_overrides=self.fake_environment(
                executable_directory, record, project, mode="nested-only"
            ),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = self.read_invocation(record)
        self.assert_workspace_invocation(invocation, project)
        self.assert_agent_snapshot_was_read_only(invocation)
        self.assert_live_target_unchanged_during_agent(invocation)
        self.assertEqual(root_manifest.read_text(encoding="utf-8"), original)
        self.assertTrue((project / "feature" / ".ctx" / "context.yaml").is_file())


@unittest.skipUnless(
    os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
    "anchored no-follow publication requires POSIX directory descriptors",
)
class RetrofitAnchoredRaceTests(unittest.TestCase):
    """Race regressions for descriptor-anchored publication and rollback."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.project = self.base / "project"
        self.outside = self.base / "outside"
        self.work = self.base / "proposal-work"
        self.project.mkdir()
        self.outside.mkdir()
        self.work.mkdir()
        root_manifest = self.project / ".ctx" / "context.yaml"
        root_manifest.parent.mkdir()
        root_manifest.write_text(
            "version: 1\n"
            "project:\n"
            "  id: race-fixture\n"
            "  name: Race Fixture\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Race Fixture\n",
            encoding="utf-8",
        )

    @staticmethod
    def nested_manifest(node_id: str, name: str) -> str:
        return (
            "version: 1\n"
            "node:\n"
            f"  id: {node_id}\n"
            f"  name: {name}\n"
        )

    def prepare(self, *node_names: str) -> tuple[retrofit_agent.ProposedManifest, ...]:
        raw_items = [
            {
                "path": f"{name}/.ctx/context.yaml",
                "content": self.nested_manifest(name, name.title()),
            }
            for name in node_names
        ]
        return retrofit_agent._prepare_proposals(
            self.project,
            raw_items,
            self.work,
        )

    def test_node_ancestor_swap_to_outside_symlink_before_publication(self) -> None:
        node = self.project / "feature"
        anchored_node = self.project / "feature-anchored"
        node.mkdir()
        proposals = self.prepare("feature")
        root_fd = retrofit_agent._open_directory_no_follow(self.project)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        real_open = retrofit_agent._open_proposed_node

        def swap_then_open(
            descriptor: int, proposal: retrofit_agent.ProposedManifest
        ) -> int:
            node.rename(anchored_node)
            node.symlink_to(self.outside, target_is_directory=True)
            return real_open(descriptor, proposal)

        try:
            with mock.patch.object(
                retrofit_agent,
                "_open_proposed_node",
                side_effect=swap_then_open,
            ) as guarded_open:
                with self.assertRaises((OSError, CtxError)):
                    retrofit_agent._publish(root_fd, proposals)
            guarded_open.assert_called_once()
        finally:
            os.close(root_fd)

        self.assertTrue(node.is_symlink())
        self.assertFalse((anchored_node / ".ctx").exists())
        self.assertFalse((self.outside / ".ctx").exists())

    def test_node_ancestor_swap_to_outside_symlink_before_rollback(self) -> None:
        alpha = self.project / "alpha"
        alpha_anchored = self.project / "alpha-anchored"
        omega = self.project / "omega"
        alpha.mkdir()
        omega.mkdir()
        outside_manifest = self.outside / ".ctx" / "context.yaml"
        outside_manifest.parent.mkdir()
        outside_manifest.write_text("OUTSIDE_CANARY\n", encoding="utf-8")
        proposals = self.prepare("alpha", "omega")
        root_fd = retrofit_agent._open_directory_no_follow(self.project)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        real_open = retrofit_agent._open_proposed_node
        calls = 0

        def fail_after_swap(
            descriptor: int, proposal: retrofit_agent.ProposedManifest
        ) -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                self.assertEqual(proposal.relative_path, "omega/.ctx/context.yaml")
                alpha.rename(alpha_anchored)
                alpha.symlink_to(self.outside, target_is_directory=True)
                raise OSError(errno.EIO, "injected publication failure")
            return real_open(descriptor, proposal)

        try:
            with mock.patch.object(
                retrofit_agent,
                "_open_proposed_node",
                side_effect=fail_after_swap,
            ) as guarded_open:
                with self.assertRaisesRegex(OSError, "injected publication failure"):
                    retrofit_agent._publish(root_fd, proposals)
            self.assertEqual(guarded_open.call_count, 2)
        finally:
            os.close(root_fd)

        self.assertTrue(alpha.is_symlink())
        self.assertFalse((alpha_anchored / ".ctx").exists())
        self.assertFalse((omega / ".ctx").exists())
        self.assertEqual(
            outside_manifest.read_text(encoding="utf-8"),
            "OUTSIDE_CANARY\n",
        )

    def test_same_inode_tamper_after_strict_validation_is_rejected(self) -> None:
        feature = self.project / "feature"
        feature.mkdir()
        proposals = self.prepare("feature")
        root_fd = retrofit_agent._open_directory_no_follow(self.project)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        created = retrofit_agent._publish(root_fd, proposals)
        target = feature / ".ctx" / "context.yaml"

        try:
            validation = retrofit_agent.validate_project(self.project, strict=True)
            self.assertTrue(validation.valid, validation.diagnostics)

            before = target.stat()
            original = target.read_bytes()
            tampered = b"x" * len(original)
            with target.open("r+b", buffering=0) as stream:
                stream.write(tampered)
            os.utime(
                target,
                ns=(before.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )
            after = target.stat()
            self.assertEqual(
                (
                    after.st_dev,
                    after.st_ino,
                    stat.S_IMODE(after.st_mode),
                    after.st_size,
                    after.st_mtime_ns,
                ),
                (
                    before.st_dev,
                    before.st_ino,
                    stat.S_IMODE(before.st_mode),
                    before.st_size,
                    before.st_mtime_ns,
                ),
                "the race fixture must differ only in manifest bytes",
            )

            with self.assertRaises(CtxError) as raised:
                retrofit_agent._verify_created_locations(root_fd, proposals, created)
            self.assertEqual(raised.exception.code, "retrofit.destination-changed")
        finally:
            retrofit_agent._release(created)
            os.close(root_fd)


if __name__ == "__main__":
    unittest.main()
