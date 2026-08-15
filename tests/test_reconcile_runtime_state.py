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


class ReconcileCodexRuntimeStateTests(unittest.TestCase):
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
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        initialized = self.run_ctx(
            "init",
            str(self.project),
            "--id",
            "reconcile-runtime",
            "--name",
            "Reconcile Runtime",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        seal_freshness(self.project)

    def run_ctx(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        child_environment = os.environ.copy()
        child_environment.update(
            {"HOME": str(self.home), "CTX_HOME": str(self.ctx_home)}
        )
        if environment:
            child_environment.update(environment)
        return subprocess.run(
            [sys.executable, "-m", "ctx", *arguments],
            cwd=self.project,
            env=child_environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def test_reconcile_uses_private_sqlite_home_outside_snapshot(self) -> None:
        executable_directory = self.base / "bin"
        executable_directory.mkdir()
        executable = executable_directory / "codex"
        record = self.base / "invocation.json"
        executable.write_text(
            f'''#!{Path(sys.executable).resolve()}
import json
import os
import stat
import sys
from pathlib import Path

arguments = sys.argv[1:]
configs = [
    arguments[index + 1]
    for index, value in enumerate(arguments[:-1])
    if value == "-c"
]
sqlite_configs = [value for value in configs if value.startswith("sqlite_home=")]
if len(sqlite_configs) != 1:
    raise SystemExit(87)
sqlite_home = Path(json.loads(sqlite_configs[0].split("=", 1)[1]))
snapshot = Path(arguments[arguments.index("-C") + 1]).resolve()
live_root = Path(os.environ["FAKE_CODEX_LIVE_ROOT"]).resolve()
if not sqlite_home.is_dir():
    raise SystemExit(88)
if sqlite_home.resolve().is_relative_to(snapshot):
    raise SystemExit(89)
if sqlite_home.resolve().is_relative_to(live_root):
    raise SystemExit(90)
if stat.S_IMODE(sqlite_home.stat().st_mode) != 0o700:
    raise SystemExit(91)
Path(os.environ["FAKE_CODEX_RECORD"]).write_text(
    json.dumps({{"sqlite_home": str(sqlite_home), "snapshot": str(snapshot)}}),
    encoding="utf-8",
)
result = Path(arguments[arguments.index("--output-last-message") + 1])
result.write_text(
    json.dumps({{
        "manifests": [],
        "acknowledgements": [{{
            "uri": "ctx://reconcile-runtime",
            "reason": "Implementation-only value change."
        }}],
        "summary": "Reviewed as implementation-only."
    }}) + "\\n",
    encoding="utf-8",
)
''',
            encoding="utf-8",
        )
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        self.source.write_text("VALUE = 2\n", encoding="utf-8")

        result = self.run_ctx(
            "reconcile",
            environment={
                "PATH": str(executable_directory),
                "FAKE_CODEX_LIVE_ROOT": str(self.project.resolve()),
                "FAKE_CODEX_RECORD": str(record),
            },
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = json.loads(record.read_text(encoding="utf-8"))
        self.assertNotEqual(invocation["sqlite_home"], invocation["snapshot"])


if __name__ == "__main__":
    unittest.main()
