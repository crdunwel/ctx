from __future__ import annotations

import subprocess
import tomllib
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class DocumentationSurfaceTests(unittest.TestCase):
    def test_development_runtime_is_pinned_and_agent_safe(self) -> None:
        agents = (REPOSITORY / "AGENTS.md").read_text(encoding="utf-8")
        contributing = (REPOSITORY / "CONTRIBUTING.md").read_text(
            encoding="utf-8"
        )
        envrc = (REPOSITORY / ".envrc").read_text(encoding="utf-8")
        codex_environment = tomllib.loads(
            (REPOSITORY / ".codex" / "environments" / "environment.toml").read_text(
                encoding="utf-8"
            )
        )
        bootstrap = REPOSITORY / "scripts" / "bootstrap"

        self.assertEqual(
            (REPOSITORY / ".python-version").read_text(encoding="utf-8").strip(),
            "3.12.6",
        )
        self.assertIn(".venv/bin/python", agents)
        self.assertIn(".venv/bin/ctx", agents)
        self.assertIn("./scripts/bootstrap", contributing)
        self.assertIn("PATH_add .venv/bin", envrc)
        self.assertEqual(codex_environment["version"], 1)
        self.assertIn("./scripts/bootstrap", codex_environment["setup"]["script"])
        self.assertTrue(bootstrap.stat().st_mode & 0o111)
        subprocess.run(["bash", "-n", str(bootstrap)], check=True)

    def test_readme_has_model_free_first_value_path(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")

        self.assertIn("versioned map of what your code means", readme)
        self.assertIn("## Why ctx", readme)
        self.assertIn("## Get value in 60 seconds", readme)
        self.assertIn("ctx demo /tmp/ctx-permit-board-demo", readme)
        self.assertIn("python -m unittest discover -s tests -q", readme)
        self.assertIn("ctx status --check", readme)
        self.assertIn('ctx hydrate --task "Explain how', readme)
        self.assertIn("ctx hydrate --from permit_board/policy", readme)
        self.assertIn("# simulated source change", readme)
        self.assertIn("without invoking a model", readme)
        self.assertIn("## Add ctx to an existing project", readme)
        self.assertIn("ctx retrofit", readme)

    def test_docs_distinguish_hooks_from_slash_commands_and_desktop(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        cli_reference = (REPOSITORY / "docs" / "CLI.md").read_text(
            encoding="utf-8"
        )

        for name, document in (("README", readme), ("CLI reference", cli_reference)):
            with self.subTest(document=name):
                normalized = " ".join(document.split())
                self.assertIn("does not install a `/ctx` slash command", normalized)
                self.assertIn("`/hooks`", normalized)
                self.assertIn("Codex CLI/TUI", normalized)
                self.assertIn(
                    "desktop app does not currently expose", normalized.lower()
                )
                self.assertIn("https://learn.chatgpt.com/docs/hooks", normalized)
                self.assertIn("user-wide or project", normalized)
                self.assertIn("multiple files concurrently", normalized)
                self.assertIn("does not create a", normalized)
                self.assertIn("ctx integrate codex --hooks --user", normalized)

    def test_docs_define_git_freshness_hook_boundaries(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        cli_reference = (REPOSITORY / "docs" / "CLI.md").read_text(
            encoding="utf-8"
        )

        for name, document in (("README", readme), ("CLI reference", cli_reference)):
            with self.subTest(document=name):
                normalized = " ".join(document.split())
                self.assertIn("ctx integrate git --hooks", normalized)
                self.assertIn("ctx reconcile", normalized)
                self.assertIn("warning", normalized.lower())
                self.assertIn("working tree", normalized.lower())
                self.assertIn("staged", normalized.lower())
                self.assertIn("never invokes a model", normalized.lower())
                self.assertIn("core.hooksPath", normalized)

    def test_docs_disclose_bounded_reconcile_diff(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        cli_reference = (REPOSITORY / "docs" / "CLI.md").read_text(
            encoding="utf-8"
        )

        for name, document in (("README", readme), ("CLI reference", cli_reference)):
            with self.subTest(document=name):
                normalized = " ".join(document.split()).lower()
                self.assertIn("bounded supplemental", normalized)
                self.assertIn("head", normalized)
                self.assertIn("working-tree", normalized)
                self.assertIn("deleted", normalized)
                self.assertIn("current source", normalized)

    def test_docs_define_guarded_agents_review_boundaries(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        cli_reference = (REPOSITORY / "docs" / "CLI.md").read_text(
            encoding="utf-8"
        )

        for name, document in (("README", readme), ("CLI reference", cli_reference)):
            with self.subTest(document=name):
                normalized = " ".join(document.split()).lower()
                self.assertIn("ctx agents review --staged", normalized)
                self.assertIn("ctx agents prompt --staged", normalized)
                self.assertIn("ctx agents show-plan", normalized)
                self.assertIn("ctx agents apply", normalized)
                self.assertIn("content-addressed", normalized)
                self.assertIn("read-only", normalized)
                self.assertIn("does not invoke", normalized)
                self.assertIn("index", normalized)
                self.assertIn("operational", normalized)
                self.assertIn("semantic", normalized)
                self.assertIn("selected change", normalized)
                self.assertIn("target", normalized)
                self.assertIn("established scope", normalized)
                self.assertIn("bounded", normalized)
                self.assertIn("fair", normalized)
                self.assertIn("every changed path", normalized)
                self.assertIn("`already-covered`", normalized)
                self.assertIn("`implementation-only`", normalized)
                self.assertIn("`requires-update`", normalized)
                self.assertIn("`insufficient-evidence`", normalized)
                self.assertIn("`no-op`", normalized)
                self.assertIn("truncated non-target", normalized)
                self.assertIn("`review-required`", normalized)
                self.assertIn("every current selected file", normalized)
                self.assertIn("may still support an update", normalized)
                self.assertIn("already exactly matches", normalized)
                self.assertIn("without rewrit", normalized)
                self.assertIn("one isolated correction", normalized)
                self.assertIn("same read-only snapshot", normalized)
                self.assertIn("historical patch", normalized)
                self.assertIn("exact-match", normalized)
                self.assertIn("old/new edit", normalized)
                self.assertIn("occur exactly once", normalized)
                self.assertIn("overlapping", normalized)
                self.assertIn("materializ", normalized)
                self.assertIn("complete proposed bytes", normalized)


if __name__ == "__main__":
    unittest.main()
