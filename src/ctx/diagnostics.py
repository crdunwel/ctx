from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    manifest: Path | None = None
    field: str | None = None
    path: Path | None = None
    fails_strict: bool = False

    def sort_key(self) -> tuple[str, str, str, str, str]:
        return (
            str(self.manifest or ""),
            self.field or "",
            self.code,
            self.severity,
            self.message,
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "fails_strict": self.fails_strict,
        }
        if self.manifest is not None:
            value["manifest"] = str(self.manifest)
        if self.field is not None:
            value["field"] = self.field
        if self.path is not None:
            value["path"] = str(self.path)
        return value


class CtxError(Exception):
    """Expected, user-facing failure."""

    def __init__(self, code: str, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


class UnsafePathError(CtxError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, exit_code=3)


class NotFoundError(CtxError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, exit_code=2)
