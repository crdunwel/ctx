from __future__ import annotations

import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .diagnostics import CtxError


@dataclass(frozen=True, slots=True)
class CodexExecutable:
    path: Path
    source: str


def _validated_executable(path: Path) -> Path | None:
    """Return a canonical executable file, or None when the candidate is absent."""

    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _macos_bundle_candidates() -> tuple[Path, ...]:
    if sys.platform != "darwin":
        return ()
    return (
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path.home() / "Applications/ChatGPT.app/Contents/Resources/codex",
    )


def find_codex_executable(
    *, environment: Mapping[str, str] | None = None
) -> CodexExecutable | None:
    """Resolve the optional Codex CLI consistently for every guarded adapter.

    An explicit CTX_CODEX value is fail-closed: a typo must not silently select a
    different executable from PATH or an application bundle.
    """

    values = os.environ if environment is None else environment
    override = values.get("CTX_CODEX")
    if override is not None:
        candidate = Path(override)
        if not override or not candidate.is_absolute():
            raise CtxError(
                "codex.executable-invalid",
                "CTX_CODEX must name an absolute executable file",
                exit_code=4,
            )
        executable = _validated_executable(candidate)
        if executable is None:
            raise CtxError(
                "codex.executable-invalid",
                f"CTX_CODEX does not name an executable file: {candidate}",
                exit_code=4,
            )
        return CodexExecutable(path=executable, source="environment")

    search_path = values.get("PATH")
    if search_path:
        discovered = shutil.which("codex", path=search_path)
        if discovered is not None:
            executable = _validated_executable(Path(discovered))
            if executable is not None:
                return CodexExecutable(path=executable, source="path")

    for candidate in _macos_bundle_candidates():
        executable = _validated_executable(candidate)
        if executable is not None:
            return CodexExecutable(path=executable, source="chatgpt-app")
    return None
