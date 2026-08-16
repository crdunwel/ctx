from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .freshness import (
    LockResult,
    initialize_freshness,
    remove_created_lock,
    restore_replaced_lock,
    seal_freshness,
)
from .integration import (
    CodexHooksInstallResult,
    ensure_codex_hooks_for_retrofit,
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
    replace_fresh_lock: bytes | None = None,
) -> RetrofitLifecycleResult:
    """Enable a retrofitted project for discovery, freshness, and Codex use.

    Hook setup is create-only and reuses canonical user-wide hooks instead of
    duplicating them at project scope. A reviewed fresh lock may be
    conditionally replaced when missing manifests are added. All lifecycle
    writes are rolled back when later work or an optional evidence guard fails.
    The guard brackets freshness sealing and registration.
    """

    hooks: CodexHooksInstallResult | None = None
    lock: LockResult | None = None
    registration: RegistrationResult | None = None
    expected_lock: bytes | None = None
    previous_lock: bytes | None = None
    try:
        if enable_codex_hooks:
            hooks = ensure_codex_hooks_for_retrofit(root)
        if verify_unchanged is not None:
            verify_unchanged()
        if replace_fresh_lock is None:
            lock = initialize_freshness(root)
        else:
            previous_lock = replace_fresh_lock
            lock = seal_freshness(
                root,
                expected_previous=replace_fresh_lock,
                mismatch_code="lock.review-baseline-changed",
                mismatch_message="freshness lock changed after the reviewed baseline",
            )
        expected_lock = lock.content
        if expected_lock is None:  # pragma: no cover - internal result contract
            raise AssertionError("freshness operation did not return exact lock bytes")
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
                if previous_lock is None:
                    remove_created_lock(lock, expected_lock)
                else:
                    restore_replaced_lock(lock, expected_lock, previous_lock)
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
