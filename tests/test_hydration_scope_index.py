from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.freshness import seal_freshness


class HydrationDormantScopeIndexTests(unittest.TestCase):
    """Contract tests for the derived immediate-child scope index."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.ctx_home = self.base / "ctx-home"
        self.root = self.base / "scope-index"
        self.alpha = self.root / "alpha"
        self.gamma = self.alpha / "gamma"
        self.deep = self.gamma / "deep"
        self.beta = self.root / "beta"

        for directory in (
            self.root,
            self.alpha,
            self.gamma,
            self.deep,
            self.beta,
        ):
            directory.mkdir()

        self._write_root()
        self._write_node(
            self.alpha,
            node_id="alpha",
            name="Alpha Scope",
            summary="ALPHA_DORMANT_CONTENT_MUST_NOT_EXPAND",
            with_artifact=True,
        )
        self._write_node(
            self.gamma,
            node_id="gamma",
            name="Gamma Scope",
            summary="GAMMA_DORMANT_CONTENT_MUST_NOT_EXPAND",
            with_artifact=True,
        )
        self._write_node(
            self.deep,
            node_id="deep",
            name="Deep Scope",
            summary="DEEP_DORMANT_CONTENT_MUST_NOT_EXPAND",
        )
        self._write_node(
            self.beta,
            node_id="beta",
            name="Beta Scope",
            summary="BETA_DORMANT_CONTENT_MUST_NOT_EXPAND",
        )

    def run_ctx(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CTX_HOME"] = str(self.ctx_home)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=self.base,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def hydrate_json(self, path: Path) -> dict[str, object]:
        result = self.run_ctx("hydrate", "--from", str(path), "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def hydrate_json_with(
        self, path: Path, *arguments: str
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        result = self.run_ctx(
            "hydrate", "--from", str(path), *arguments, "--json"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result, json.loads(result.stdout)

    def _write_root(self) -> None:
        context = self.root / ".ctx"
        context.mkdir()
        (context / "context.yaml").write_text(
            """version: 1
project:
  id: scope-index
  name: Scope Index
  aliases: []
node:
  id: root
  name: Scope Index Root
  summary: Root content is active only at the project root.
items:
  - id: root-invariant
    kind: invariant
    title: Root invariant
    summary: This constraint is inherited by active descendants.
""",
            encoding="utf-8",
        )

    def _write_node(
        self,
        directory: Path,
        *,
        node_id: str,
        name: str,
        summary: str,
        with_artifact: bool = False,
    ) -> None:
        context = directory / ".ctx"
        context.mkdir()
        artifact = ""
        item_artifact = ""
        if with_artifact:
            (directory / "implementation.txt").write_text(
                f"{node_id} implementation\n", encoding="utf-8"
            )
            artifact = (
                "artifacts:\n"
                "  - path: implementation.txt\n"
                f"    role: {node_id.upper()}_DORMANT_ARTIFACT_MUST_NOT_EXPAND.\n"
            )
            item_artifact = "    artifacts: [implementation.txt]\n"
        (context / "context.yaml").write_text(
            "version: 1\n"
            "node:\n"
            f"  id: {node_id}\n"
            f"  name: {name}\n"
            f"  summary: {summary}\n"
            f"{artifact}"
            "items:\n"
            f"  - id: {node_id}-pattern\n"
            "    kind: pattern\n"
            f"    title: {name} pattern\n"
            f"    summary: {node_id.upper()}_DORMANT_ITEM_MUST_NOT_EXPAND\n"
            f"{item_artifact}",
            encoding="utf-8",
        )

    @staticmethod
    def scope(uri: str, name: str, directory: Path) -> dict[str, str]:
        return {
            "uri": uri,
            "name": name,
            "directory": str(directory.resolve()),
        }

    def test_index_lists_only_immediate_children_without_expanding_content(self) -> None:
        root_payload = self.hydrate_json(self.root)
        self.assertEqual(
            root_payload["dormant_scopes"],
            [
                self.scope("ctx://scope-index/alpha", "Alpha Scope", self.alpha),
                self.scope("ctx://scope-index/beta", "Beta Scope", self.beta),
            ],
        )
        self.assertEqual(
            set(root_payload["dormant_scopes"][0]),
            {"uri", "name", "directory"},
        )
        serialized = json.dumps(root_payload, sort_keys=True)
        for dormant_content in (
            "ALPHA_DORMANT_CONTENT_MUST_NOT_EXPAND",
            "ALPHA_DORMANT_ARTIFACT_MUST_NOT_EXPAND",
            "ALPHA_DORMANT_ITEM_MUST_NOT_EXPAND",
            "GAMMA_DORMANT_CONTENT_MUST_NOT_EXPAND",
            "DEEP_DORMANT_CONTENT_MUST_NOT_EXPAND",
            "ctx://scope-index/alpha/gamma",
            "ctx://scope-index/alpha/gamma/deep",
        ):
            self.assertNotIn(dormant_content, serialized)

        alpha_payload = self.hydrate_json(self.alpha)
        self.assertEqual(
            alpha_payload["dormant_scopes"],
            [
                self.scope(
                    "ctx://scope-index/alpha/gamma",
                    "Gamma Scope",
                    self.gamma,
                )
            ],
        )
        alpha_serialized = json.dumps(alpha_payload, sort_keys=True)
        self.assertNotIn("BETA_DORMANT_CONTENT_MUST_NOT_EXPAND", alpha_serialized)
        self.assertNotIn("DEEP_DORMANT_CONTENT_MUST_NOT_EXPAND", alpha_serialized)
        self.assertNotIn("ctx://scope-index/alpha/gamma/deep", alpha_serialized)

        beta_payload = self.hydrate_json(self.beta)
        self.assertEqual(beta_payload["dormant_scopes"], [])

        markdown = self.run_ctx("hydrate", "--from", str(self.root))
        self.assertEqual(markdown.returncode, 0, markdown.stdout + markdown.stderr)
        self.assertIn("ctx://scope-index/alpha", markdown.stdout)
        self.assertIn("ctx://scope-index/beta", markdown.stdout)
        self.assertNotIn("ctx://scope-index/alpha/gamma", markdown.stdout)
        self.assertNotIn("ALPHA_DORMANT_CONTENT_MUST_NOT_EXPAND", markdown.stdout)
        self.assertNotIn("ALPHA_DORMANT_ARTIFACT_MUST_NOT_EXPAND", markdown.stdout)
        self.assertNotIn("ALPHA_DORMANT_ITEM_MUST_NOT_EXPAND", markdown.stdout)

    def test_index_is_rederived_deterministically_after_rename_add_and_remove(self) -> None:
        initial = self.hydrate_json(self.root)
        self.assertEqual(
            [scope["uri"] for scope in initial["dormant_scopes"]],
            ["ctx://scope-index/alpha", "ctx://scope-index/beta"],
        )

        renamed_beta = self.root / "renamed-beta"
        self.beta.rename(renamed_beta)
        renamed = self.hydrate_json(self.root)
        self.assertEqual(
            renamed["dormant_scopes"],
            [
                self.scope("ctx://scope-index/alpha", "Alpha Scope", self.alpha),
                self.scope("ctx://scope-index/beta", "Beta Scope", renamed_beta),
            ],
        )
        self.assertEqual(renamed["active_scope"]["uri"], "ctx://scope-index")

        added = self.root / "aardvark-directory"
        added.mkdir()
        self._write_node(
            added,
            node_id="zulu",
            name="Zulu Scope",
            summary="ZULU_DORMANT_CONTENT_MUST_NOT_EXPAND",
        )
        after_add = self.hydrate_json(self.root)
        self.assertEqual(
            [scope["uri"] for scope in after_add["dormant_scopes"]],
            [
                "ctx://scope-index/alpha",
                "ctx://scope-index/beta",
                "ctx://scope-index/zulu",
            ],
        )

        (renamed_beta / ".ctx" / "context.yaml").unlink()
        after_remove = self.hydrate_json(self.root)
        self.assertEqual(
            after_remove["dormant_scopes"],
            [
                self.scope("ctx://scope-index/alpha", "Alpha Scope", self.alpha),
                self.scope("ctx://scope-index/zulu", "Zulu Scope", added),
            ],
        )
        repeated = self.hydrate_json(self.root)
        self.assertEqual(repeated["dormant_scopes"], after_remove["dormant_scopes"])
        self.assertEqual(repeated["active_scope"], after_remove["active_scope"])

    def test_exact_immediate_child_selection_removes_it_from_dormant_routes(self) -> None:
        alpha_uri = "ctx://scope-index/alpha"
        commands = (
            ("positional URI", (alpha_uri,)),
            ("include", ("--include", alpha_uri)),
            ("task URI", ("--task", f"Work in {alpha_uri}")),
            ("positional path", (str(self.alpha),)),
        )

        for label, arguments in commands:
            with self.subTest(selection=label):
                _result, payload = self.hydrate_json_with(self.root, *arguments)
                self.assertEqual(
                    [scope["uri"] for scope in payload["dormant_scopes"]],
                    ["ctx://scope-index/beta"],
                )
                selected = next(
                    node for node in payload["nodes"] if node["uri"] == alpha_uri
                )
                self.assertEqual(selected["role"], "requested")
                self.assertEqual(selected["detail"], "expanded")
                self.assertIn(
                    "ALPHA_DORMANT_CONTENT_MUST_NOT_EXPAND",
                    json.dumps(selected, sort_keys=True),
                )

    def test_grandchild_path_selection_removes_rendered_immediate_ancestor(self) -> None:
        _result, payload = self.hydrate_json_with(self.root, str(self.gamma))

        self.assertEqual(
            [scope["uri"] for scope in payload["dormant_scopes"]],
            ["ctx://scope-index/beta"],
        )
        by_uri = {node["uri"]: node for node in payload["nodes"]}
        self.assertEqual(by_uri["ctx://scope-index/alpha"]["role"], "ancestor")
        self.assertEqual(by_uri["ctx://scope-index/alpha"]["detail"], "ancestor")
        self.assertEqual(
            by_uri["ctx://scope-index/alpha/gamma"]["role"], "requested"
        )
        self.assertNotIn(
            "GAMMA_DORMANT_CONTENT_MUST_NOT_EXPAND",
            json.dumps(payload["dormant_scopes"], sort_keys=True),
        )

    def test_malformed_child_graph_omits_index_with_warning(self) -> None:
        broken = self.root / "broken"
        (broken / ".ctx").mkdir(parents=True)
        (broken / ".ctx" / "context.yaml").write_text(
            "version: 1\nnode: malformed\n",
            encoding="utf-8",
        )

        _result, payload = self.hydrate_json_with(self.root)

        self.assertEqual(payload["dormant_scopes"], [])
        self.assertEqual(
            [node["uri"] for node in payload["nodes"]], ["ctx://scope-index"]
        )
        self.assertTrue(
            any(
                "dormant" in warning.casefold()
                and "omit" in warning.casefold()
                for warning in payload["warnings"]
            ),
            payload["warnings"],
        )

        markdown = self.run_ctx("hydrate", "--from", str(self.root))
        self.assertEqual(markdown.returncode, 0, markdown.stdout + markdown.stderr)
        self.assertIn("WARNING:", markdown.stdout)
        self.assertNotIn("Available child scopes (dormant)", markdown.stdout)

    def test_duplicate_child_graph_omits_index_with_warning(self) -> None:
        duplicate = self.root / "duplicate-alpha"
        duplicate.mkdir()
        self._write_node(
            duplicate,
            node_id="alpha",
            name="Duplicate Alpha Scope",
            summary="DUPLICATE_ALPHA_MUST_NOT_ROUTE",
        )

        _result, payload = self.hydrate_json_with(self.root)

        self.assertEqual(payload["dormant_scopes"], [])
        self.assertTrue(
            any(
                "dormant" in warning.casefold()
                and "omit" in warning.casefold()
                for warning in payload["warnings"]
            ),
            payload["warnings"],
        )
        self.assertNotIn("DUPLICATE_ALPHA_MUST_NOT_ROUTE", json.dumps(payload))

    def test_many_children_are_truncated_to_budget_with_omitted_count(self) -> None:
        added_children = 60
        for index in range(added_children):
            directory = self.root / f"budget-child-{index:02d}-long-directory-name"
            directory.mkdir()
            self._write_node(
                directory,
                node_id=f"scope-{index:02d}",
                name=f"Budget Child {index:02d} With A Deliberately Long Routing Name",
                summary=f"BUDGET_CHILD_{index:02d}_CONTENT_MUST_NOT_EXPAND",
            )

        _result, payload = self.hydrate_json_with(
            self.root, "--budget", "500"
        )
        total_children = added_children + 2
        included = len(payload["dormant_scopes"])
        omitted = total_children - included

        self.assertGreater(included, 0)
        self.assertGreater(omitted, 0)
        self.assertFalse(payload["over_budget"])
        self.assertEqual(payload["dormant_scopes_omitted"], omitted)
        self.assertFalse(payload["dormant_scopes_complete"])
        rendered_routes = json.dumps(payload["dormant_scopes"], sort_keys=True)
        self.assertNotIn("_CONTENT_MUST_NOT_EXPAND", rendered_routes)

        markdown = self.run_ctx(
            "hydrate", "--from", str(self.root), "--budget", "500"
        )
        self.assertEqual(markdown.returncode, 0, markdown.stdout + markdown.stderr)
        self.assertLessEqual(len(markdown.stdout), 500 * 4)
        self.assertIn(str(omitted), markdown.stdout)
        self.assertIn("omit", markdown.stdout.casefold())

    def test_empty_child_directory_rename_after_seal_is_not_fresh(self) -> None:
        seal_freshness(self.root)
        before = self.run_ctx("status", str(self.root), "--check", "--json")
        self.assertEqual(before.returncode, 0, before.stdout + before.stderr)
        self.assertTrue(json.loads(before.stdout)["fresh"])

        renamed_beta = self.root / "renamed-empty-beta"
        self.beta.rename(renamed_beta)

        after = self.run_ctx("status", str(self.root), "--check", "--json")
        self.assertEqual(after.returncode, 1, after.stdout + after.stderr)
        payload = json.loads(after.stdout)
        self.assertFalse(payload["fresh"])
        beta = next(
            node for node in payload["nodes"] if node["uri"] == "ctx://scope-index/beta"
        )
        self.assertNotEqual(beta["state"], "fresh")


if __name__ == "__main__":
    unittest.main()
