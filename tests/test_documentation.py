from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class DocumentationSurfaceTests(unittest.TestCase):
    def test_readme_has_model_free_first_value_path(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")

        self.assertIn("## Get value in 60 seconds", readme)
        self.assertIn('ctx hydrate --task "Explain how', readme)
        self.assertIn("without invoking a model", readme)

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


if __name__ == "__main__":
    unittest.main()
