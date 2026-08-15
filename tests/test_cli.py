from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from ctx.schema import parse_manifest
from ctx.yamlio import dump_yaml


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"

    def run_ctx(
        self, *arguments: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CTX_HOME"] = str(self.ctx_home)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=cwd or self.base,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def init_project(self, name: str = "project") -> Path:
        root = self.base / name
        root.mkdir()
        result = self.run_ctx(
            "init",
            str(root),
            "--id",
            name,
            "--name",
            name.replace("-", " ").title(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return root

    def write_manifest(self, node_dir: Path, text: str) -> Path:
        ctx_dir = node_dir / ".ctx"
        ctx_dir.mkdir(exist_ok=True)
        path = ctx_dir / "context.yaml"
        path.write_text(text, encoding="utf-8")
        return path


class InitTests(CliTestCase):
    def test_init_explicit_identity_and_idempotency(self) -> None:
        root = self.base / "permit"
        root.mkdir()
        first = self.run_ctx(
            "init",
            str(root),
            "--id",
            "permit-atlas",
            "--name",
            "Permit Atlas",
            "--alias",
            "permits",
            "--alias",
            "permit atlas",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        manifest_path = root / ".ctx" / "context.yaml"
        before = manifest_path.read_bytes()
        data = yaml.safe_load(before)
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["project"]["id"], "permit-atlas")
        self.assertEqual(data["project"]["aliases"], ["permits", "permit atlas"])
        self.assertEqual(data["node"], {"id": "root", "name": "Permit Atlas"})
        self.assertFalse((root / ".ctx" / "lock.json").exists())

        second = self.run_ctx("init", str(root))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("unchanged", second.stdout)
        self.assertEqual(manifest_path.read_bytes(), before)

    def test_init_conflict_is_non_destructive(self) -> None:
        root = self.init_project()
        manifest = root / ".ctx" / "context.yaml"
        before = manifest.read_bytes()
        result = self.run_ctx("init", str(root), "--id", "other")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(manifest.read_bytes(), before)

    def test_init_rejects_invalid_id_without_partial_manifest(self) -> None:
        root = self.base / "bad"
        root.mkdir()
        result = self.run_ctx("init", str(root), "--id", "Bad ID")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((root / ".ctx" / "context.yaml").exists())

    def test_init_infers_deterministic_identity(self) -> None:
        root = self.base / "My App"
        root.mkdir()
        result = self.run_ctx("init", str(root))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = yaml.safe_load((root / ".ctx" / "context.yaml").read_text())
        self.assertEqual(data["project"]["id"], "my-app")
        self.assertEqual(data["project"]["name"], "My App")

    def test_init_refuses_nested_project(self) -> None:
        root = self.init_project()
        child = root / "child"
        child.mkdir()
        result = self.run_ctx("init", str(child), "--id", "child")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((child / ".ctx" / "context.yaml").exists())


class NodeAndDiscoveryTests(CliTestCase):
    def test_node_init_and_deep_ancestry(self) -> None:
        root = self.init_project()
        source = root / "src"
        forms = source / "forms"
        deep = forms / "components"
        deep.mkdir(parents=True)
        source_result = self.run_ctx(
            "node", "init", str(source), "--id", "domain", "--name", "Domain"
        )
        forms_result = self.run_ctx(
            "node",
            "init",
            str(forms),
            "--id",
            "forms",
            "--name",
            "Forms",
            "--summary",
            "Progressive form system.",
        )
        self.assertEqual(source_result.returncode, 0, source_result.stderr)
        self.assertEqual(forms_result.returncode, 0, forms_result.stderr)
        nested = yaml.safe_load((forms / ".ctx" / "context.yaml").read_text())
        self.assertNotIn("project", nested)
        self.assertFalse((forms / ".ctx" / "lock.json").exists())

        shown = self.run_ctx("show", str(deep), "--json")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        payload = json.loads(shown.stdout)
        self.assertEqual(
            [node["uri"] for node in payload["nodes"]],
            ["ctx://project", "ctx://project/domain", "ctx://project/domain/forms"],
        )
        self.assertEqual(payload["current_node_uri"], "ctx://project/domain/forms")
        self.assertEqual(payload["validation"], {"valid": True, "errors": 0, "warnings": 0})

    def test_show_accepts_file_and_does_not_include_siblings(self) -> None:
        root = self.init_project()
        left = root / "left"
        right = root / "right"
        left.mkdir()
        right.mkdir()
        self.assertEqual(
            self.run_ctx(
                "node", "init", str(left), "--id", "left", "--name", "Left"
            ).returncode,
            0,
        )
        self.assertEqual(
            self.run_ctx(
                "node", "init", str(right), "--id", "right", "--name", "Right"
            ).returncode,
            0,
        )
        source = left / "module.py"
        source.write_text("VALUE = 1\n")
        shown = self.run_ctx("show", str(source), "--json")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        uris = [node["uri"] for node in json.loads(shown.stdout)["nodes"]]
        self.assertEqual(uris, ["ctx://project", "ctx://project/left"])

    def test_node_init_is_non_destructive_and_requires_project(self) -> None:
        orphan = self.base / "orphan"
        orphan.mkdir()
        missing = self.run_ctx(
            "node", "init", str(orphan), "--id", "forms", "--name", "Forms"
        )
        self.assertEqual(missing.returncode, 2)
        self.assertFalse((orphan / ".ctx").exists())

        root = self.init_project()
        child = root / "forms"
        child.mkdir()
        first = self.run_ctx(
            "node", "init", str(child), "--id", "forms", "--name", "Forms"
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        manifest = child / ".ctx" / "context.yaml"
        before = manifest.read_bytes()
        same = self.run_ctx(
            "node", "init", str(child), "--id", "forms", "--name", "Forms"
        )
        conflict = self.run_ctx(
            "node", "init", str(child), "--id", "other", "--name", "Other"
        )
        self.assertEqual(same.returncode, 0, same.stderr)
        self.assertEqual(conflict.returncode, 1)
        self.assertEqual(manifest.read_bytes(), before)

    def test_sibling_semantic_uri_collision_is_refused(self) -> None:
        root = self.init_project()
        first = root / "first"
        second = root / "second"
        first.mkdir()
        second.mkdir()
        self.assertEqual(
            self.run_ctx(
                "node", "init", str(first), "--id", "forms", "--name", "Forms"
            ).returncode,
            0,
        )
        result = self.run_ctx(
            "node", "init", str(second), "--id", "forms", "--name", "Other Forms"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("node.uri-collision", result.stderr)
        self.assertFalse((second / ".ctx" / "context.yaml").exists())

    def test_path_symlink_cannot_escape_project(self) -> None:
        root = self.init_project()
        outside = self.base / "outside"
        outside.mkdir()
        link = root / "escape"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        result = self.run_ctx("show", str(link), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "path.symlink-escape")

    def test_symlink_cannot_switch_to_an_external_ctx_project(self) -> None:
        root = self.init_project()
        outside = self.init_project("external")
        link = root / "escape"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        result = self.run_ctx("show", str(link), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn(
            json.loads(result.stdout)["error"]["code"],
            {"path.symlink-escape", "path.symlink-project-switch"},
        )


class ValidationTests(CliTestCase):
    def test_full_manifest_and_inherited_items(self) -> None:
        root = self.init_project()
        forms = root / "src" / "forms"
        forms.mkdir(parents=True)
        (forms / "FormShell.tsx").write_text("export const FormShell = {};\n")
        (forms / "fields.ts").write_text("export const fields = [];\n")
        self.write_manifest(
            forms,
            """\
version: 1
node:
  id: forms
  name: Form system
  summary: Mobile-first progressive forms.
artifacts:
  - path: FormShell.tsx
    role: Main progressive form container.
  - path: fields.ts
    role: Canonical field configuration.
items:
  - id: progressive-form-shell
    kind: pattern
    title: Progressive form shell
    summary: Configuration-driven multi-step form.
    artifacts: [FormShell.tsx, fields.ts]
    adoption:
      mode: adapt
      requires: [stable field identifiers]
      verify: [progress survives refresh]
  - id: stable-field-identifiers
    kind: invariant
    title: Stable field identifiers
    summary: Field identifiers require explicit migrations.
    artifacts: [fields.ts]
  - id: configuration-driven-fields
    kind: decision
    title: Configuration-driven fields
    summary: Form structure is configuration.
    artifacts: [FormShell.tsx, fields.ts]
    reason: Keeps rendering and validation aligned.
""",
        )
        result = self.run_ctx("validate", str(forms), "--strict", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["summary"]["nodes"], 2)
        shown = self.run_ctx("show", str(forms))
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("Progressive form shell", shown.stdout)
        self.assertIn("Stable field identifiers", shown.stdout)
        self.assertIn(str(forms / "FormShell.tsx"), shown.stdout)

        shown_json = self.run_ctx("show", str(forms), "--json")
        self.assertEqual(shown_json.returncode, 0, shown_json.stderr)
        items = {
            item["id"]: item
            for item in json.loads(shown_json.stdout)["nodes"][-1]["items"]
        }
        self.assertEqual(items["stable-field-identifiers"]["artifacts"], ["fields.ts"])
        self.assertEqual(
            items["configuration-driven-fields"]["artifacts"],
            ["FormShell.tsx", "fields.ts"],
        )

        manifest_path = forms / ".ctx" / "context.yaml"
        raw_text = manifest_path.read_text(encoding="utf-8")
        parsed, diagnostics = parse_manifest(
            yaml.safe_load(raw_text), manifest_path, raw_text=raw_text
        )
        self.assertIsNotNone(parsed)
        self.assertFalse(diagnostics)
        assert parsed is not None
        round_trip_text = dump_yaml(parsed.to_dict())
        round_tripped, round_trip_diagnostics = parse_manifest(
            yaml.safe_load(round_trip_text), manifest_path, raw_text=round_trip_text
        )
        self.assertFalse(round_trip_diagnostics)
        self.assertEqual(round_tripped, parsed)

    def test_every_item_artifact_requires_a_top_level_artifact_role(self) -> None:
        root = self.init_project()
        (root / "declared.py").write_text("DECLARED = True\n")
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["artifacts"] = [
            {"path": "declared.py", "role": "Canonical implementation."}
        ]
        data["items"] = [
            {
                "id": "unsupported-invariant",
                "kind": "invariant",
                "title": "Unsupported invariant",
                "summary": "This evidence reference is not declared.",
                "artifacts": ["invariant.py"],
            },
            {
                "id": "unsupported-decision",
                "kind": "decision",
                "title": "Unsupported decision",
                "summary": "This evidence reference is not declared.",
                "artifacts": ["decision.py"],
            },
            {
                "id": "unsupported-pattern",
                "kind": "pattern",
                "title": "Unsupported pattern",
                "summary": "This evidence reference is not declared.",
                "artifacts": ["pattern.py"],
            },
        ]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))

        result = self.run_ctx("validate", str(root), "--strict", "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        diagnostics = json.loads(result.stdout)["diagnostics"]
        undeclared = [
            diagnostic
            for diagnostic in diagnostics
            if diagnostic["code"] == "item.artifact-undeclared"
        ]
        self.assertEqual(len(undeclared), 3)
        self.assertEqual(
            {diagnostic["field"] for diagnostic in undeclared},
            {
                "items[0].artifacts[0]",
                "items[1].artifacts[0]",
                "items[2].artifacts[0]",
            },
        )

    def test_unknown_field_warns_and_strict_promotes(self) -> None:
        root = self.init_project()
        manifest = root / ".ctx" / "context.yaml"
        manifest.write_text(manifest.read_text() + "instructions: run-this\n")
        ordinary = self.run_ctx("validate", str(root), "--json")
        strict = self.run_ctx("validate", str(root), "--strict", "--json")
        self.assertEqual(ordinary.returncode, 0, ordinary.stdout)
        self.assertTrue(json.loads(ordinary.stdout)["valid"])
        self.assertEqual(strict.returncode, 1, strict.stdout)
        strict_payload = json.loads(strict.stdout)
        self.assertFalse(strict_payload["valid"])
        self.assertEqual(strict.stderr, "")
        self.assertIn(
            "schema.unknown-field",
            {item["code"] for item in strict_payload["diagnostics"]},
        )

    def test_duplicate_key_and_unsafe_yaml_are_rejected(self) -> None:
        for text in (
            """\
version: 1
version: 1
project: {id: sample, name: Sample, aliases: []}
node: {id: root, name: Sample}
""",
            """\
!!python/object/apply:os.system ['touch should-not-exist']
""",
            """\
version: &version 1
project: {id: sample, name: Sample, aliases: []}
node: {id: root, name: Sample}
copy: *version
""",
            """\
version: 1
project: {id: sample, name: Sample, aliases: []}
node: {id: root, name: Sample}
---
version: 1
""",
        ):
            with self.subTest(text=text):
                root = self.base / f"bad-{len(list(self.base.iterdir()))}"
                root.mkdir()
                self.write_manifest(root, text)
                result = self.run_ctx("validate", str(root), "--json")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(json.loads(result.stdout)["schema"], "ctx-error/v1")
        self.assertFalse((self.base / "should-not-exist").exists())

    def test_exact_scalar_types_are_required(self) -> None:
        root = self.base / "types"
        root.mkdir()
        self.write_manifest(
            root,
            """\
version: true
project: {id: sample, name: Sample, aliases: []}
node: {id: root, name: Sample}
links:
  - target: ctx://sample
    relation: related_to
    optional: "false"
""",
        )
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(json.loads(result.stdout)["schema"], "ctx-error/v1")

    def test_excessive_yaml_depth_is_a_manifest_error(self) -> None:
        root = self.base / "deep-yaml"
        root.mkdir()
        nested = "[" * 80 + "x" + "]" * 80
        self.write_manifest(
            root,
            "version: 1\n"
            "project: {id: sample, name: Sample, aliases: []}\n"
            "node: {id: root, name: Sample}\n"
            f"extra: {nested}\n",
        )
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "ctx-error/v1")
        self.assertEqual(payload["error"]["code"], "manifest.invalid")

    def test_artifact_missing_and_secret_are_invalid(self) -> None:
        root = self.init_project()
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["artifacts"] = [
            {"path": "missing.py", "role": "Missing canonical source."},
            {"path": ".env", "role": "Must never be exposed."},
        ]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("artifact.missing", codes)
        self.assertIn("artifact.secret", codes)

    def test_artifact_may_traverse_within_project_but_not_escape(self) -> None:
        root = self.init_project()
        shared = root / "shared.json"
        shared.write_text("{}\n")
        child = root / "src" / "forms"
        child.mkdir(parents=True)
        self.write_manifest(
            child,
            """\
version: 1
node: {id: forms, name: Forms}
artifacts:
  - path: ../../shared.json
    role: Shared schema.
""",
        )
        valid = self.run_ctx("validate", str(root), "--strict", "--json")
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        child_manifest = child / ".ctx" / "context.yaml"
        child_manifest.write_text(child_manifest.read_text().replace("../../shared.json", "../../../outside"))
        invalid = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(invalid.returncode, 3, invalid.stdout + invalid.stderr)
        codes = {item["code"] for item in json.loads(invalid.stdout)["diagnostics"]}
        self.assertIn("path.escape", codes)

    def test_missing_artifact_below_external_symlink_is_unsafe(self) -> None:
        root = self.init_project()
        outside = self.base / "outside"
        outside.mkdir()
        link = root / "jump"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["artifacts"] = [
            {"path": "jump/not-created.py", "role": "Must remain inside the project."}
        ]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("path.symlink-escape", codes)

    def test_secret_artifact_cannot_be_disguised_by_internal_symlink(self) -> None:
        root = self.init_project()
        secret = root / ".env"
        secret.write_text("TOKEN=hidden\n")
        alias = root / "safe.txt"
        try:
            alias.symlink_to(secret)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["artifacts"] = [{"path": "safe.txt", "role": "Disguised secret."}]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("artifact.secret", codes)

    def test_artifact_symlink_dotdot_cannot_escape(self) -> None:
        root = self.init_project()
        outside = self.base / "outside-tree"
        child = outside / "child"
        child.mkdir(parents=True)
        (outside / "data.txt").write_text("outside\n")
        link = root / "link"
        try:
            link.symlink_to(child, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["artifacts"] = [
            {"path": "link/../data.txt", "role": "Must remain inside the project."}
        ]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("path.symlink-escape", codes)

    def test_tracking_include_cannot_escape_via_symlink(self) -> None:
        root = self.init_project()
        outside = self.base / "tracking-outside"
        outside.mkdir()
        jump = root / "jump"
        try:
            jump.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["tracking"] = {"include": ["jump/data.json"]}
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("path.symlink-escape", codes)

    def test_nested_manifest_cannot_redefine_project_or_root_id(self) -> None:
        root = self.init_project()
        child = root / "child"
        child.mkdir()
        self.write_manifest(
            child,
            """\
version: 1
project: {id: nested, name: Nested, aliases: []}
node: {id: root, name: Nested root}
""",
        )
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 1, result.stdout)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("manifest.nested-project", codes)
        self.assertIn("manifest.nested-root-id", codes)

    def test_external_links_are_parsed_but_resolution_is_deferred_in_milestone_one(self) -> None:
        root = self.base / "permit"
        root.mkdir()
        self.write_manifest(
            root,
            """\
version: 1
project:
  id: permit-atlas
  name: Permit Atlas
  aliases: [permit atlas, permits]
node: {id: root, name: Permit Atlas}
links:
  - target: ctx://shared/form-accessibility
    relation: governed_by
""",
        )
        result = self.run_ctx("validate", str(root), "--strict", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["valid"])
        self.assertIn(
            "link.external-deferred",
            {item["code"] for item in payload["diagnostics"]},
        )

    def test_required_local_link_and_optional_link(self) -> None:
        root = self.init_project()
        manifest = root / ".ctx" / "context.yaml"
        data = yaml.safe_load(manifest.read_text())
        data["links"] = [
            {
                "target": "ctx://project/missing",
                "relation": "depends_on",
            },
            {
                "target": "ctx://project/optional",
                "relation": "related_to",
                "optional": True,
            },
        ]
        manifest.write_text(yaml.safe_dump(data, sort_keys=False))
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 1, result.stdout)
        payload = json.loads(result.stdout)
        codes = {item["code"] for item in payload["diagnostics"]}
        self.assertIn("link.unresolved", codes)
        self.assertIn("link.optional-unresolved", codes)

    def test_supersedes_link_cycles_are_rejected(self) -> None:
        root = self.init_project()
        left = root / "left"
        right = root / "right"
        left.mkdir()
        right.mkdir()
        self.write_manifest(
            left,
            """\
version: 1
node: {id: left, name: Left}
links:
  - target: ctx://project/right
    relation: supersedes
""",
        )
        self.write_manifest(
            right,
            """\
version: 1
node: {id: right, name: Right}
links:
  - target: ctx://project/left
    relation: supersedes
""",
        )
        result = self.run_ctx("validate", str(root), "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        codes = {item["code"] for item in json.loads(result.stdout)["diagnostics"]}
        self.assertIn("supersedes.cycle", codes)

    def test_json_output_is_machine_clean_on_usage_error(self) -> None:
        result = self.run_ctx("validate", str(self.base / "missing"), "--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["schema"], "ctx-error/v1")


if __name__ == "__main__":
    unittest.main()
