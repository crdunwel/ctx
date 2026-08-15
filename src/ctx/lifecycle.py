from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .freshness import LockResult, initialize_freshness, remove_created_lock
from .integration import (
    CodexHooksInstallResult,
    install_codex_hooks,
    remove_created_codex_hooks,
)
from .registry import RegistrationResult, register_project, rollback_registration


@dataclass(frozen=True, slots=True)
class RetrofitLifecycleResult:
    registration: RegistrationResult
    lock: LockResult
    hooks: CodexHooksInstallResult | None


def complete_retrofit(
    root: Path,
    *,
    enable_codex_hooks: bool = True,
    verify_unchanged: Callable[[], None] | None = None,
) -> RetrofitLifecycleResult:
    """Enable a retrofitted project for discovery, freshness, and Codex use.

    Project hooks and the initial lock are create-only repository state. All
    lifecycle writes are rolled back when later work or an optional evidence
    guard fails. The guard brackets freshness sealing and registration.
    """

    hooks: CodexHooksInstallResult | None = None
    lock: LockResult | None = None
    registration: RegistrationResult | None = None
    expected_lock: bytes | None = None
    try:
        if enable_codex_hooks:
            hooks = install_codex_hooks(project=root)
        if verify_unchanged is not None:
            verify_unchanged()
        lock = initialize_freshness(root)
        expected_lock = lock.path.read_bytes()
        if verify_unchanged is not None:
            verify_unchanged()
        registration = register_project(root)
        if verify_unchanged is not None:
            verify_unchanged()
    except Exception as original:
        rollback_error: Exception | None = None
        if registration is not None:
            try:
                rollback_registration(registration)
            except Exception as exc:  # pragma: no cover - defensive rollback boundary
                rollback_error = exc
        if lock is not None and expected_lock is not None:
            try:
                remove_created_lock(lock, expected_lock)
            except Exception as exc:  # pragma: no cover - defensive rollback boundary
                rollback_error = rollback_error or exc
        if hooks is not None:
            try:
                remove_created_codex_hooks(hooks)
            except Exception as exc:  # pragma: no cover - defensive rollback boundary
                rollback_error = rollback_error or exc
        if rollback_error is not None:
            raise rollback_error from original
        raise
    assert lock is not None  # created or verified before registration
    return RetrofitLifecycleResult(registration, lock, hooks)
