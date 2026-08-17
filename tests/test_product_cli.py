from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctx.freshness import seal_freshness


class ProductCliTests(unittest.TestCase):
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
            timeout=15,
            check=False,
        )

    def init(self, name: str, *, alias: str | None = None) -> Path:
        root = self.base / name
        root.mkdir()
        arguments = ["init", str(root), "--id", name, "--name", name.title()]
        if alias:
            arguments.extend(["--alias", alias])
        result = self.run_ctx(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        return root

    def set_registry_policy(
        self,
        project_id: str,
        *,
        trust: str = "trusted",
        reuse_policy: str = "code-allowed",
    ) -> None:
        registry_path = self.ctx_home / "registry.json"
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        entry = payload["projects"][project_id]
        entry["trust"] = trust
        entry["reuse_policy"] = reuse_policy
        registry_path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def init_hydration_scope_project(self) -> tuple[Path, Path, Path]:
        root = self.init("scope")
        alpha = root / "alpha"
        beta = root / "beta"
        alpha.mkdir()
        beta.mkdir()
        (root / "root.txt").write_text("root\n", encoding="utf-8")
        (alpha / "alpha.py").write_text("ALPHA = True\n", encoding="utf-8")
        (beta / "beta.py").write_text("BETA = True\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            """version: 1
project:
  id: scope
  name: Scope
  aliases: []
node:
  id: root
  name: Scope Root
  summary: Project-wide purpose inherited by narrower regions.
artifacts:
  - path: root.txt
    role: Root-only authoritative artifact.
items:
  - id: root-pattern
    kind: pattern
    title: Root pattern
    summary: A reusable root implementation pattern.
  - id: root-invariant
    kind: invariant
    title: Root invariant
    summary: Every nested scope must preserve this rule.
  - id: root-decision
    kind: decision
    title: Root decision
    summary: A project-wide architectural choice.
    reason: The whole project relies on it.
links:
  - target: ctx://scope/alpha#alpha-pattern
    relation: related_to
  - target: ctx://scope/beta#beta-pattern
    relation: related_to
""",
            encoding="utf-8",
        )
        (alpha / ".ctx").mkdir()
        (alpha / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: alpha
  name: Alpha
  summary: The active Alpha project region.
artifacts:
  - path: alpha.py
    role: Alpha implementation.
items:
  - id: alpha-pattern
    kind: pattern
    title: Alpha pattern
    summary: Alpha's complete local implementation pattern.
    artifacts: [alpha.py]
  - id: alpha-invariant
    kind: invariant
    title: Alpha invariant
    summary: Alpha's local constraint.
links:
  - target: ctx://scope/beta#beta-pattern
    relation: related_to
""",
            encoding="utf-8",
        )
        (beta / ".ctx").mkdir()
        (beta / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: beta
  name: Beta
  summary: A sibling project region.
artifacts:
  - path: beta.py
    role: Beta implementation.
items:
  - id: beta-pattern
    kind: pattern
    title: Beta pattern
    summary: Beta's reusable local implementation pattern.
    artifacts: [beta.py]
  - id: beta-invariant
    kind: invariant
    title: Beta invariant
    summary: Beta's local constraint.
""",
            encoding="utf-8",
        )
        return root, alpha, beta

    def test_global_and_per_command_help(self) -> None:
        global_help = self.run_ctx("help")
        show_help = self.run_ctx("help", "show")
        alternate = self.run_ctx("show", "help")
        self.assertEqual(global_help.returncode, 0, global_help.stderr)
        self.assertIn("hydrate", global_help.stdout)
        self.assertIn("reconcile", global_help.stdout)
        self.assertIn("positional arguments:", show_help.stdout)
        self.assertIn("options:", show_help.stdout)
        self.assertIn("REFERENCE", show_help.stdout)
        self.assertEqual(show_help.stdout, alternate.stdout)
        for command in (
            "demo",
            "init",
            "node",
            "show",
            "validate",
            "register",
            "unregister",
            "projects",
            "resolve",
            "search",
            "graph",
            "hydrate",
            "status",
            "begin",
            "doctor",
            "reconcile",
            "retrofit",
            "agents",
            "hook",
            "integrate",
        ):
            with self.subTest(command=command):
                result = self.run_ctx("help", command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("options:", result.stdout)
        retrofit_help = self.run_ctx("help", "retrofit")
        self.assertIn("--apply PLAN_ID", retrofit_help.stdout)
        self.assertIn("--show-plan PLAN_ID", retrofit_help.stdout)
        self.assertIn("--no-hooks", retrofit_help.stdout)
        self.assertIn("canonical Codex hooks", retrofit_help.stdout)
        self.assertIn("reuse an exact user-wide installation", retrofit_help.stdout)
        self.assertIn("model provider", retrofit_help.stdout)
        self.assertIn("not secret-content detection", retrofit_help.stdout)
        self.assertNotIn("default: None", retrofit_help.stdout)
        reconcile_help = self.run_ctx("help", "reconcile", "inspect")
        self.assertEqual(reconcile_help.returncode, 0, reconcile_help.stderr)
        normalized_reconcile_help = " ".join(reconcile_help.stdout.split())
        self.assertIn("--run RUN_ID", reconcile_help.stdout)
        self.assertIn("--acknowledge-node REFERENCE", reconcile_help.stdout)
        self.assertIn("model provider", normalized_reconcile_help)
        self.assertIn("model-free handoff", normalized_reconcile_help)
        incompatible = self.run_ctx("reconcile", "--prompt", "--dry-run")
        self.assertEqual(incompatible.returncode, 1)
        self.assertIn("not allowed with argument", incompatible.stderr)
        codex_hook_help = self.run_ctx("help", "hook", "codex-stop")
        self.assertEqual(codex_hook_help.returncode, 0, codex_hook_help.stderr)
        self.assertIn("Codex Stop event", codex_hook_help.stdout)
        integrate_help = self.run_ctx("help", "integrate", "codex")
        self.assertEqual(integrate_help.returncode, 0, integrate_help.stderr)
        normalized_integrate_help = " ".join(integrate_help.stdout.split())
        self.assertIn("--hooks", integrate_help.stdout)
        self.assertIn("hook process PATH", normalized_integrate_help)

        agents_help = self.run_ctx("help", "agents")
        agents_review_help = self.run_ctx("help", "agents", "review")
        agents_prompt_help = self.run_ctx("help", "agents", "prompt")
        agents_show_help = self.run_ctx("help", "agents", "show-plan")
        agents_apply_help = self.run_ctx("help", "agents", "apply")
        for result in (
            agents_help,
            agents_review_help,
            agents_prompt_help,
            agents_show_help,
            agents_apply_help,
        ):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("show-plan", agents_help.stdout)
        self.assertIn("--staged", agents_review_help.stdout)
        self.assertIn("--since REF", agents_review_help.stdout)
        self.assertIn("--run ID", agents_review_help.stdout)
        self.assertIn("no project file", agents_review_help.stdout.casefold())
        self.assertNotIn("default: None", agents_review_help.stdout)
        self.assertIn("print the exact prompt", agents_prompt_help.stdout)
        self.assertIn("PLAN_ID", agents_show_help.stdout)
        self.assertIn("No model is invoked", agents_apply_help.stdout)
        agents_selector_conflict = self.run_ctx(
            "agents", "prompt", "--staged", "--since", "HEAD"
        )
        self.assertEqual(agents_selector_conflict.returncode, 1)
        self.assertIn("not allowed with argument", agents_selector_conflict.stderr)

    def test_doctor_is_read_only_and_machine_readable(self) -> None:
        result = self.run_ctx("doctor", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "ctx-doctor/v1")
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["codex_hooks"])
        self.assertFalse(self.ctx_home.exists())

        human = self.run_ctx("doctor")
        self.assertEqual(human.returncode, 0, human.stdout + human.stderr)
        self.assertIn("Ctx project: none found from .", human.stdout)

    def test_direct_node_and_default_show(self) -> None:
        root = self.init("direct-node")
        child = root / "feature"
        child.mkdir()
        node = self.run_ctx(
            "node", str(child), "--id", "feature", "--name", "Feature"
        )
        shown = self.run_ctx("show", cwd=child)
        self.assertEqual(node.returncode, 0, node.stderr)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("ctx://direct-node/feature", shown.stdout)

    def test_registry_resolution_search_and_uri_show(self) -> None:
        root = self.init("permit-atlas", alias="permits")
        registered = self.run_ctx("register", str(root))
        resolved = self.run_ctx("resolve", "permits", "--json")
        searched = self.run_ctx("search", "permit atlas", "--json")
        shown = self.run_ctx("show", "ctx://permit-atlas", "--json")
        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        self.assertEqual(json.loads(resolved.stdout)["uri"], "ctx://permit-atlas")
        self.assertEqual(searched.returncode, 0, searched.stderr)
        self.assertTrue(json.loads(searched.stdout)["results"])
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["selected_uri"], "ctx://permit-atlas")

    def test_search_reports_match_and_policy_metadata(self) -> None:
        root = self.init("signal", alias="signal project")
        feature = root / "feature"
        feature.mkdir()
        (feature / ".ctx").mkdir()
        (feature / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: feature
  name: Camera permissions
  summary: Onboarding camera permission behavior.
""",
            encoding="utf-8",
        )
        self.assertEqual(self.run_ctx("register", str(root)).returncode, 0)
        self.set_registry_policy(
            "signal", trust="untrusted", reuse_policy="reference-only"
        )

        result = self.run_ctx(
            "search", "camera permissions", "--project", "signal", "--json"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        hit = json.loads(result.stdout)["results"][0]
        self.assertEqual(hit["uri"], "ctx://signal/feature")
        self.assertEqual(hit["trust"], "untrusted")
        self.assertEqual(hit["reuse_policy"], "reference-only")
        self.assertEqual(hit["match"]["kind"], "title-exact")
        self.assertEqual(hit["match"]["field"], "node.name")
        self.assertEqual(hit["match"]["tokens"], ["camera", "permissions"])

        partial = self.run_ctx(
            "search", "camera migration", "--project", "signal", "--json"
        )
        self.assertEqual(partial.returncode, 0, partial.stdout + partial.stderr)
        partial_hits = json.loads(partial.stdout)["results"]
        self.assertTrue(partial_hits)
        self.assertTrue(all(value["score"] < 2_000 for value in partial_hits))

    def test_external_path_include_requires_registered_policy_checked_checkout(self) -> None:
        local = self.init("local")
        external = self.init("external")
        unregistered = self.init("unregistered")

        rejected = self.run_ctx(
            "hydrate",
            "--from",
            str(local),
            "--include",
            str(unregistered),
            "--json",
        )
        self.assertEqual(rejected.returncode, 3, rejected.stdout + rejected.stderr)
        self.assertEqual(
            json.loads(rejected.stdout)["error"]["code"],
            "reference.external-path-unregistered",
        )

        self.assertEqual(self.run_ctx("register", str(external)).returncode, 0)
        self.set_registry_policy(
            "external", trust="untrusted", reuse_policy="reference-only"
        )
        accepted = self.run_ctx(
            "hydrate",
            "--from",
            str(local),
            "--include",
            str(external),
            "--json",
        )
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        external_node = json.loads(accepted.stdout)["nodes"][-1]
        self.assertEqual(external_node["uri"], "ctx://external")
        self.assertTrue(external_node["external"])
        self.assertEqual(external_node["trust"], "untrusted")
        self.assertEqual(external_node["reuse_policy"], "reference-only")

        self.set_registry_policy("external", reuse_policy="prohibited")
        (external / ".ctx" / "context.yaml").write_text(
            "this manifest is deliberately invalid: [\n", encoding="utf-8"
        )
        commands = (
            ("resolve", "external", "--json"),
            ("graph", "ctx://external", "--json"),
            ("search", "external", "--project", "external", "--json"),
            (
                "hydrate",
                "--from",
                str(local),
                "--include",
                str(external),
                "--json",
            ),
        )
        for command in commands:
            with self.subTest(command=command):
                denied = self.run_ctx(*command)
                self.assertEqual(denied.returncode, 3, denied.stdout + denied.stderr)
                self.assertEqual(
                    json.loads(denied.stdout)["error"]["code"],
                    "policy.prohibited",
                )

        global_search = self.run_ctx("search", "external", "--json")
        self.assertEqual(global_search.returncode, 0, global_search.stderr)
        self.assertEqual(json.loads(global_search.stdout)["results"], [])

    def test_hydrate_is_local_by_default_and_explicitly_external(self) -> None:
        permit = self.init("permit-atlas", alias="permit atlas")
        new_app = self.init("new-app")
        self.assertEqual(self.run_ctx("register", str(permit)).returncode, 0)
        local = self.run_ctx("hydrate", "--from", str(new_app))
        external = self.run_ctx(
            "hydrate",
            "--from",
            str(new_app),
            "--include",
            "permit atlas",
        )
        self.assertEqual(local.returncode, 0, local.stderr)
        self.assertNotIn("ctx://permit-atlas", local.stdout)
        self.assertEqual(external.returncode, 0, external.stderr)
        self.assertIn("ctx://permit-atlas", external.stdout)

    def test_task_named_project_selects_relevant_item_not_unrelated_node(self) -> None:
        permit = self.init("permit-atlas", alias="Permit Atlas")
        forms = permit / "forms"
        billing = permit / "billing"
        forms.mkdir()
        billing.mkdir()
        (forms / "FormShell.tsx").write_text("export const FormShell = {}\n", encoding="utf-8")
        (billing / "Billing.ts").write_text("export const billing = {}\n", encoding="utf-8")
        (forms / ".ctx").mkdir()
        (forms / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: forms
  name: Forms
  summary: Progressive forms for structured intake.
artifacts:
  - path: FormShell.tsx
    role: Canonical progressive form shell.
items:
  - id: progressive-form-shell
    kind: pattern
    title: Progressive form shell
    summary: Configuration-driven multi-step form flow.
    artifacts: [FormShell.tsx]
    adoption:
      mode: adapt
      requires: [stable field identifiers]
      verify: [progress survives refresh]
""",
            encoding="utf-8",
        )
        (billing / ".ctx").mkdir()
        (billing / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: billing
  name: Billing
  summary: Payment and invoice workflows.
artifacts:
  - path: Billing.ts
    role: Billing workflow implementation.
""",
            encoding="utf-8",
        )
        new_app = self.init("new-app")
        self.assertEqual(self.run_ctx("register", str(permit)).returncode, 0)
        result = self.run_ctx(
            "hydrate",
            "--from",
            str(new_app),
            "--task",
            "Use the form pattern from Permit Atlas",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ctx://permit-atlas/forms", result.stdout)
        self.assertIn("Progressive form shell", result.stdout)
        self.assertIn("stable field identifiers", result.stdout)
        self.assertIn(str(forms / "FormShell.tsx"), result.stdout)
        self.assertNotIn("ctx://permit-atlas/billing", result.stdout)

    def test_task_named_project_expands_only_unique_strong_scope(self) -> None:
        atlas = self.init("atlas", alias="Permit Atlas")
        for node_id, name, summary in (
            ("camera", "Camera permissions", "Camera access and denial behavior."),
            ("onboarding", "Onboarding", "First-run setup behavior."),
            ("alpha", "Alpha", "Shared workflow for catalog intake."),
            ("beta", "Beta", "Shared workflow for inventory intake."),
        ):
            directory = atlas / node_id
            directory.mkdir()
            (directory / ".ctx").mkdir()
            (directory / ".ctx" / "context.yaml").write_text(
                f"""version: 1
node:
  id: {node_id}
  name: {name}
  summary: {summary}
""",
                encoding="utf-8",
            )
        consumer = self.init("consumer")
        self.assertEqual(self.run_ctx("register", str(atlas)).returncode, 0)

        strong = self.run_ctx(
            "hydrate",
            "--from",
            str(consumer),
            "--task",
            "Use camera permissions from Permit Atlas",
            "--json",
        )
        self.assertEqual(strong.returncode, 0, strong.stdout + strong.stderr)
        strong_payload = json.loads(strong.stdout)
        self.assertEqual(
            [node["uri"] for node in strong_payload["nodes"]],
            ["ctx://consumer", "ctx://atlas/camera"],
        )
        self.assertEqual(strong_payload["warnings"], [])

        weak = self.run_ctx(
            "hydrate",
            "--from",
            str(consumer),
            "--task",
            "Use onboarding camera permissions from Permit Atlas",
            "--json",
        )
        self.assertEqual(weak.returncode, 0, weak.stdout + weak.stderr)
        weak_payload = json.loads(weak.stdout)
        self.assertEqual(
            [node["uri"] for node in weak_payload["nodes"]],
            ["ctx://consumer", "ctx://atlas"],
        )
        self.assertTrue(
            any(
                "matched context only weakly" in value
                for value in weak_payload["warnings"]
            )
        )

        ambiguous = self.run_ctx(
            "hydrate",
            "--from",
            str(consumer),
            "--task",
            "Use shared workflow from Permit Atlas",
            "--json",
        )
        self.assertEqual(ambiguous.returncode, 0, ambiguous.stdout + ambiguous.stderr)
        ambiguous_payload = json.loads(ambiguous.stdout)
        self.assertEqual(
            [node["uri"] for node in ambiguous_payload["nodes"]],
            ["ctx://consumer", "ctx://atlas"],
        )
        self.assertTrue(
            any("is ambiguous" in value for value in ambiguous_payload["warnings"])
        )

    def test_hydrate_is_scope_driven_and_keeps_links_as_references(self) -> None:
        root, alpha, _beta = self.init_hydration_scope_project()

        root_result = self.run_ctx("hydrate", "--from", str(root), "--json")
        self.assertEqual(root_result.returncode, 0, root_result.stdout + root_result.stderr)
        root_payload = json.loads(root_result.stdout)
        self.assertEqual([node["uri"] for node in root_payload["nodes"]], ["ctx://scope"])
        self.assertEqual(root_payload["schema"], "ctx-hydration/v2")
        self.assertEqual(
            root_payload["active_scope"],
            {
                "uri": "ctx://scope",
                "directory": str(root.resolve()),
                "from": str(root.resolve()),
            },
        )
        self.assertEqual(root_payload["nodes"][0]["detail"], "expanded")
        self.assertEqual(root_payload["nodes"][0]["role"], "current")
        self.assertIn("ctx hydrate --from <file-or-directory> --task <task>", root_payload["scope_guidance"])

        nested_result = self.run_ctx("hydrate", "--from", str(alpha), "--json")
        self.assertEqual(
            nested_result.returncode, 0, nested_result.stdout + nested_result.stderr
        )
        payload = json.loads(nested_result.stdout)
        self.assertEqual(
            [node["uri"] for node in payload["nodes"]],
            ["ctx://scope", "ctx://scope/alpha"],
        )
        ancestor, current = payload["nodes"]
        self.assertEqual(ancestor["detail"], "ancestor")
        self.assertEqual(ancestor["role"], "ancestor")
        self.assertEqual(ancestor["artifacts"], [])
        self.assertEqual(
            [item["id"] for item in ancestor["items"]],
            ["root-invariant", "root-decision"],
        )
        self.assertEqual(current["detail"], "expanded")
        self.assertEqual(current["role"], "current")
        self.assertEqual([item["id"] for item in current["items"]], ["alpha-pattern", "alpha-invariant"])
        self.assertEqual([artifact["path"] for artifact in current["artifacts"]], ["alpha.py"])
        self.assertNotIn("ctx://scope/beta", [node["uri"] for node in payload["nodes"]])
        self.assertEqual(
            [link["target"] for link in ancestor["links"]],
            ["ctx://scope/alpha#alpha-pattern", "ctx://scope/beta#beta-pattern"],
        )

        markdown = self.run_ctx("hydrate", "--from", str(alpha))
        self.assertEqual(markdown.returncode, 0, markdown.stdout + markdown.stderr)
        self.assertIn("detail=ancestor", markdown.stdout)
        self.assertIn("Link references (not expanded):", markdown.stdout)
        self.assertIn("ctx hydrate --from <file-or-directory> --task <task>", markdown.stdout)
        self.assertNotIn("Root-only authoritative artifact", markdown.stdout)
        self.assertNotIn("Root pattern", markdown.stdout)

    def test_local_task_exact_item_expands_without_waking_siblings(self) -> None:
        root, _alpha, _beta = self.init_hydration_scope_project()
        for node_id in ("data", "fix", "test"):
            directory = root / node_id
            directory.mkdir()
            (directory / ".ctx").mkdir()
            (directory / ".ctx" / "context.yaml").write_text(
                f"""version: 1
node:
  id: {node_id}
  name: {node_id.title()}
""",
                encoding="utf-8",
            )

        exact = self.run_ctx(
            "hydrate",
            "--from",
            str(root),
            "--task",
            "Apply the Beta pattern",
            "--json",
        )
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        exact_payload = json.loads(exact.stdout)
        self.assertEqual(
            [node["uri"] for node in exact_payload["nodes"]],
            ["ctx://scope", "ctx://scope/beta"],
        )
        requested = exact_payload["nodes"][-1]
        self.assertEqual(requested["role"], "requested")
        self.assertEqual(
            [item["id"] for item in requested["items"]],
            ["beta-pattern", "beta-invariant"],
        )
        self.assertNotIn(
            "ctx://scope/alpha", [node["uri"] for node in exact_payload["nodes"]]
        )

        ordinary = self.run_ctx(
            "hydrate",
            "--from",
            str(root),
            "--task",
            "Fix data test behavior",
            "--json",
        )
        self.assertEqual(ordinary.returncode, 0, ordinary.stdout + ordinary.stderr)
        self.assertEqual(
            [node["uri"] for node in json.loads(ordinary.stdout)["nodes"]],
            ["ctx://scope"],
        )

        peer = self.run_ctx(
            "hydrate",
            "--from",
            str(root / "alpha"),
            "--task",
            "Use the Beta scope",
            "--json",
        )
        self.assertEqual(peer.returncode, 0, peer.stdout + peer.stderr)
        self.assertEqual(
            [node["uri"] for node in json.loads(peer.stdout)["nodes"]],
            ["ctx://scope", "ctx://scope/alpha", "ctx://scope/beta"],
        )

        weak = self.run_ctx(
            "hydrate",
            "--from",
            str(root),
            "--task",
            "Work on reusable behavior",
            "--json",
        )
        self.assertEqual(weak.returncode, 0, weak.stdout + weak.stderr)
        self.assertEqual(
            [node["uri"] for node in json.loads(weak.stdout)["nodes"]],
            ["ctx://scope"],
        )

    def test_hydrate_expands_an_exact_explicit_link_target(self) -> None:
        _root, alpha, _beta = self.init_hydration_scope_project()
        target = "ctx://scope/beta#beta-pattern"

        commands = (
            ("hydrate", target, "--from", str(alpha), "--json"),
            ("hydrate", "--from", str(alpha), "--include", target, "--json"),
            (
                "hydrate",
                "--from",
                str(alpha),
                "--task",
                f"Apply {target} here",
                "--json",
            ),
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.run_ctx(*command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                nodes = json.loads(result.stdout)["nodes"]
                self.assertEqual(
                    [node["uri"] for node in nodes],
                    ["ctx://scope", "ctx://scope/alpha", "ctx://scope/beta"],
                )
                selected = nodes[-1]
                self.assertEqual(selected["detail"], "expanded")
                self.assertEqual(selected["role"], "requested")
                self.assertEqual(
                    [item["id"] for item in selected["items"]],
                    ["beta-pattern", "beta-invariant"],
                )
                self.assertEqual(
                    [artifact["path"] for artifact in selected["artifacts"]],
                    ["beta.py"],
                )

        constrained = self.run_ctx(
            "hydrate",
            target,
            "--from",
            str(alpha),
            "--task",
            "x" * 3_000,
            "--budget",
            "500",
            "--json",
        )
        self.assertEqual(constrained.returncode, 0, constrained.stdout + constrained.stderr)
        constrained_payload = json.loads(constrained.stdout)
        self.assertTrue(constrained_payload["over_budget"])
        self.assertEqual(
            [node["uri"] for node in constrained_payload["nodes"]],
            ["ctx://scope", "ctx://scope/alpha", "ctx://scope/beta"],
        )

    def test_hydrate_three_level_scope_compacts_every_ancestor(self) -> None:
        root, alpha, _beta = self.init_hydration_scope_project()
        gamma = alpha / "gamma"
        gamma.mkdir()
        (gamma / "gamma.py").write_text("GAMMA = True\n", encoding="utf-8")
        (gamma / ".ctx").mkdir()
        (gamma / ".ctx" / "context.yaml").write_text(
            """version: 1
node:
  id: gamma
  name: Gamma
  summary: The most specific active region.
artifacts:
  - path: gamma.py
    role: Gamma implementation.
items:
  - id: gamma-pattern
    kind: pattern
    title: Gamma pattern
    summary: Gamma's local implementation pattern.
    artifacts: [gamma.py]
  - id: gamma-invariant
    kind: invariant
    title: Gamma invariant
    summary: Gamma's local constraint.
""",
            encoding="utf-8",
        )

        result = self.run_ctx("hydrate", "--from", str(gamma), "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        nodes = json.loads(result.stdout)["nodes"]
        self.assertEqual(
            [node["uri"] for node in nodes],
            ["ctx://scope", "ctx://scope/alpha", "ctx://scope/alpha/gamma"],
        )
        self.assertEqual([node["role"] for node in nodes], ["ancestor", "ancestor", "current"])
        self.assertEqual(nodes[0]["artifacts"], [])
        self.assertEqual(nodes[1]["artifacts"], [])
        self.assertEqual([item["id"] for item in nodes[1]["items"]], ["alpha-invariant"])
        self.assertEqual(
            [item["id"] for item in nodes[2]["items"]],
            ["gamma-pattern", "gamma-invariant"],
        )
        self.assertEqual([artifact["path"] for artifact in nodes[2]["artifacts"]], ["gamma.py"])

    def test_status_detects_source_change_and_fresh_noop_reconcile(self) -> None:
        root = self.init("freshness")
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        seal_freshness(root)
        fresh = self.run_ctx("status", str(root), "--check", "--json")
        self.assertEqual(fresh.returncode, 0, fresh.stdout + fresh.stderr)
        source.write_text("VALUE = 2\n", encoding="utf-8")
        stale = self.run_ctx("status", str(root), "--check", "--json")
        self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)
        self.assertEqual(json.loads(stale.stdout)["nodes"][0]["state"], "stale")

        # Acknowledgement-only reconciliation still requires the agent for a
        # stale node, but a genuinely fresh project is a two-word no-op.
        source.write_text("VALUE = 1\n", encoding="utf-8")
        no_op = self.run_ctx("reconcile", str(root))
        self.assertEqual(no_op.returncode, 0, no_op.stderr)
        self.assertIn("already fresh", no_op.stdout)

    def test_status_unknown_before_initial_lock(self) -> None:
        root = self.init("unknown-lock")
        result = self.run_ctx("status", str(root), "--check", "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["fresh"])
        self.assertEqual(payload["nodes"][0]["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
