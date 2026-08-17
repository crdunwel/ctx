from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .diagnostics import CtxError, UnsafePathError
from .discovery import find_project_root


_HOOK_NAME = "pre-commit"
_MAX_GIT_OUTPUT = 65_536
_MAX_EXISTING_HOOK_SIZE = 1_048_576


@dataclass(frozen=True, slots=True)
class GitHookInstallResult:
    action: Literal["created", "unchanged"]
    path: Path
    project_root: Path
    git_common_dir: Path
    blocking: bool


def _canonical_pre_commit_hook(*, block: bool) -> bytes:
    blocking = "1" if block else "0"
    return f"""#!/bin/sh
# Installed by ctx. This hook only checks deterministic freshness.

ctx_block_commits={blocking}
project_root=$(git rev-parse --show-toplevel 2>/dev/null)
git_status=$?
if [ "$git_status" -ne 0 ] || [ -z "$project_root" ]; then
  echo "ctx pre-commit: cannot determine the Git worktree root." >&2
  if [ "$ctx_block_commits" -eq 1 ]; then
    echo "ctx pre-commit: commit blocked." >&2
    exit 1
  fi
  echo "ctx pre-commit: warning only; commit allowed." >&2
  exit 0
fi

# A common Git hooks directory can serve branches or linked worktrees where
# ctx is intentionally absent. A manifest deleted from a ctx-enabled branch is
# different: keep warning or blocking until that removal is handled explicitly.
if [ ! -f "$project_root/.ctx/context.yaml" ]; then
  ctx_manifest_expected=0
  git -C "$project_root" ls-files --error-unmatch -- .ctx/context.yaml >/dev/null 2>&1 && ctx_manifest_expected=1
  git -C "$project_root" cat-file -e HEAD:.ctx/context.yaml >/dev/null 2>&1 && ctx_manifest_expected=1
  if [ "$ctx_manifest_expected" -eq 1 ]; then
    echo "ctx pre-commit: the tracked root .ctx/context.yaml is missing." >&2
    echo "Restore it and run ctx reconcile, or remove this hook for an intentional ctx decommission." >&2
    if [ "$ctx_block_commits" -eq 1 ]; then
      echo "ctx pre-commit: commit blocked." >&2
      exit 1
    fi
    echo "ctx pre-commit: warning only; commit allowed." >&2
  fi
  exit 0
fi

if ! command -v ctx >/dev/null 2>&1; then
  echo "ctx pre-commit: ctx is not available on PATH." >&2
  if [ "$ctx_block_commits" -eq 1 ]; then
    echo "ctx pre-commit: commit blocked." >&2
    exit 1
  fi
  echo "ctx pre-commit: warning only; commit allowed." >&2
  exit 0
fi

# Blocking mode only claims staged-snapshot enforcement when the index and
# working tree agree. Otherwise ctx status would inspect a mixed checkout.
if [ "$ctx_block_commits" -eq 1 ]; then
  ctx_worktree_mixed=0
  git -C "$project_root" diff --quiet -- || ctx_worktree_mixed=1
  ctx_untracked=$(git -C "$project_root" ls-files --others --exclude-standard)
  ctx_untracked_status=$?
  if [ "$ctx_untracked_status" -ne 0 ] || [ -n "$ctx_untracked" ]; then
    ctx_worktree_mixed=1
  fi
  if [ "$ctx_worktree_mixed" -ne 0 ]; then
    echo "ctx pre-commit: blocking mode cannot verify partial staging or untracked files." >&2
    echo "Stage or stash all tracked changes and nonignored untracked files, then retry." >&2
    echo "ctx pre-commit: commit blocked." >&2
    exit 1
  fi
fi

ctx status "$project_root" --check >/dev/null 2>&1
ctx_status=$?
if [ "$ctx_status" -ne 0 ]; then
  echo "ctx pre-commit: context is stale, unknown, or invalid." >&2
  echo "Run: ctx reconcile" >&2
  echo "Then review and stage any .ctx changes before retrying the commit." >&2
  if [ "$ctx_block_commits" -eq 1 ]; then
    echo "ctx pre-commit: commit blocked." >&2
    exit "$ctx_status"
  fi
  echo "ctx pre-commit: warning only; commit allowed." >&2
  exit 0
fi

# A fresh worktree is not enough if reconciliation output remains outside the
# index: the resulting commit would version source with older ctx evidence.
ctx_unstaged=0
git -C "$project_root" diff --quiet -- ':(glob)**/.ctx/**' || ctx_unstaged=1
ctx_untracked=$(git -C "$project_root" ls-files --others --exclude-standard -- ':(glob)**/.ctx/**')
ctx_untracked_status=$?
if [ "$ctx_untracked_status" -ne 0 ] || [ -n "$ctx_untracked" ]; then
  ctx_unstaged=1
fi
if [ "$ctx_unstaged" -ne 0 ]; then
  echo "ctx pre-commit: context changes are not staged." >&2
  echo "Review and git-add the intended .ctx files so context is versioned with this commit." >&2
  if [ "$ctx_block_commits" -eq 1 ]; then
    echo "ctx pre-commit: commit blocked." >&2
    exit 1
  fi
  echo "ctx pre-commit: warning only; commit allowed." >&2
fi
exit 0
""".encode("utf-8")


def _git(
    root: Path,
    arguments: list[str],
    *,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CtxError(
            "git.unavailable",
            "Git is required to install the ctx pre-commit hook",
            exit_code=4,
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise CtxError(
            "git.command-failed",
            f"could not inspect Git hook configuration for {root}: {exc}",
            exit_code=4,
        ) from exc
    if len(completed.stdout) > _MAX_GIT_OUTPUT or len(completed.stderr) > _MAX_GIT_OUTPUT:
        raise CtxError(
            "git.output-too-large",
            f"Git returned unexpectedly large hook configuration output for {root}",
            exit_code=4,
        )
    if completed.returncode not in allowed_returncodes:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        suffix = f": {detail}" if detail else ""
        raise CtxError(
            "git.repository-required",
            f"ctx Git hook integration requires a non-bare Git worktree at {root}{suffix}",
            exit_code=1,
        )
    try:
        output = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafePathError(
            "git.path-invalid",
            f"Git returned a non-UTF-8 path for {root}",
        ) from exc
    if "\x00" in output or any(
        ord(character) < 32 and character not in {"\n", "\r", "\t"}
        for character in output
    ):
        raise UnsafePathError(
            "git.path-invalid",
            f"Git returned an unsafe path for {root}",
        )
    return completed.returncode, output.rstrip("\r\n")


def _git_path(root: Path, arguments: list[str]) -> Path:
    _returncode, value = _git(root, arguments)
    if not value or "\n" in value or "\r" in value:
        raise UnsafePathError(
            "git.path-invalid",
            f"Git returned an invalid path for {root}",
        )
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return Path(os.path.abspath(os.fspath(candidate)))


def _configured_hooks_path(root: Path) -> str | None:
    returncode, value = _git(
        root,
        ["config", "--get", "core.hooksPath"],
        allowed_returncodes=(0, 1),
    )
    return value if returncode == 0 else None


def _read_existing_hook(path: Path, expected: bytes) -> Literal["missing", "same", "different"]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        raise CtxError(
            "git.hook-read-failed",
            f"cannot inspect existing Git hook {path}: {exc}",
            exit_code=4,
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise UnsafePathError(
            "git.hook-symlink",
            f"Git pre-commit hook cannot be a symlink: {path}",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafePathError(
            "git.hook-not-file",
            f"Git pre-commit hook is not a regular file: {path}",
        )
    if metadata.st_size > _MAX_EXISTING_HOOK_SIZE:
        return "different"
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise CtxError(
            "git.hook-read-failed",
            f"cannot read existing Git hook {path}: {exc}",
            exit_code=4,
        ) from exc
    if content != expected:
        return "different"
    if not metadata.st_mode & stat.S_IXUSR:
        raise CtxError(
            "git.hook-not-executable",
            f"the canonical ctx pre-commit hook exists but is not executable: {path}",
            exit_code=1,
        )
    return "same"


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short write while publishing Git hook")
        offset += written


def _publish_hook(path: Path, content: bytes) -> Literal["created", "unchanged"]:
    state = _read_existing_hook(path, content)
    if state == "same":
        return "unchanged"
    if state == "different":
        raise CtxError(
            "git.hook-conflict",
            f"Git pre-commit hook already exists with different content and was not replaced: {path}",
            exit_code=1,
        )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        try:
            descriptor = os.open(path, flags, 0o755)
        except FileExistsError:
            raced = _read_existing_hook(path, content)
            if raced == "same":
                return "unchanged"
            if raced == "different":
                raise CtxError(
                    "git.hook-conflict",
                    f"Git pre-commit hook appeared with different content and was not replaced: {path}",
                    exit_code=1,
                )
            raise CtxError(
                "git.hook-write-failed",
                f"Git pre-commit hook could not be published safely: {path}",
                exit_code=4,
            )
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(descriptor, 0o755)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except CtxError:
        raise
    except OSError as exc:
        if created_identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == created_identity:
                    path.unlink()
            except OSError:
                pass
        raise CtxError(
            "git.hook-write-failed",
            f"cannot publish Git pre-commit hook {path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return "created"


def install_git_pre_commit_hook(
    project: Path | None = None, *, block: bool = False
) -> GitHookInstallResult:
    """Install the deterministic ctx freshness check without replacing hooks.

    Git stores default hooks in its common directory. That is also the correct
    location for linked worktrees, where the per-worktree Git directory is a
    separate administrative directory. The hook derives the current worktree
    root when invoked, so one canonical hook is safe across those worktrees.
    """

    project_root, _project = find_project_root(project or Path.cwd())
    git_root = _git_path(project_root, ["rev-parse", "--show-toplevel"])
    try:
        resolved_git_root = git_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError(
            "git.root-invalid",
            f"cannot resolve Git worktree root safely: {git_root}: {exc}",
        ) from exc
    if resolved_git_root != project_root:
        raise CtxError(
            "git.project-root-mismatch",
            "ctx pre-commit integration requires the ctx project root to match "
            f"the Git worktree root ({project_root} != {resolved_git_root})",
            exit_code=3,
        )

    configured = _configured_hooks_path(project_root)
    if configured is not None:
        rendered = configured or "<empty>"
        raise CtxError(
            "git.hooks-path-configured",
            "core.hooksPath is configured and may be shared, so ctx did not write to it: "
            f"{rendered}",
            exit_code=3,
        )

    common_lexical = _git_path(project_root, ["rev-parse", "--git-common-dir"])
    hooks_lexical = _git_path(project_root, ["rev-parse", "--git-path", "hooks"])
    expected_hooks_lexical = common_lexical / "hooks"
    if hooks_lexical != expected_hooks_lexical:
        raise UnsafePathError(
            "git.hooks-path-unsafe",
            f"Git hooks path is not the default common hooks directory: {hooks_lexical}",
        )
    try:
        common_dir = common_lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError(
            "git.common-dir-invalid",
            f"cannot resolve Git common directory safely: {common_lexical}: {exc}",
        ) from exc
    if not common_dir.is_dir():
        raise UnsafePathError(
            "git.common-dir-invalid",
            f"Git common directory is not a directory: {common_dir}",
        )

    hooks_dir = common_dir / "hooks"
    directory_created = False
    try:
        if hooks_dir.is_symlink():
            raise UnsafePathError(
                "git.hooks-directory-symlink",
                f"Git hooks directory cannot be a symlink: {hooks_dir}",
            )
        if hooks_dir.exists():
            if not hooks_dir.is_dir():
                raise UnsafePathError(
                    "git.hooks-directory-not-directory",
                    f"Git hooks path is not a directory: {hooks_dir}",
                )
        else:
            try:
                hooks_dir.mkdir(mode=0o755)
                directory_created = True
            except FileExistsError:
                if hooks_dir.is_symlink() or not hooks_dir.is_dir():
                    raise UnsafePathError(
                        "git.hooks-directory-unsafe",
                        f"Git hooks path changed while it was being created: {hooks_dir}",
                    )
            except OSError as exc:
                raise CtxError(
                    "git.hooks-directory-failed",
                    f"cannot create Git hooks directory {hooks_dir}: {exc}",
                    exit_code=4,
                ) from exc

        hook_path = hooks_dir / _HOOK_NAME
        action = _publish_hook(hook_path, _canonical_pre_commit_hook(block=block))
    except Exception:
        if directory_created:
            try:
                hooks_dir.rmdir()
            except OSError:
                pass
        raise
    return GitHookInstallResult(action, hook_path, project_root, common_dir, block)
