from __future__ import annotations

import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .diagnostics import CtxError, NotFoundError, UnsafePathError
from .discovery import find_project_root
from .freshness import project_status, seal_freshness
from .integration import install_codex_hooks
from .paths import absolute_lexical
from .validation import validate_project


@dataclass(frozen=True, slots=True)
class DemoResult:
    root: Path
    manifests: tuple[Path, ...]
    hooks: Path
    lock: Path


_DEMO_FILES = {
    "README.md": """# Permit Board Demo

This tiny service decides whether a permit application is ready for staff
review. It keeps application identity and orchestration at the project root and
puts fee and eligibility meaning in a narrower policy boundary.

The review order is deliberate:

1. A parcel identifier is required.
2. The required fee is calculated deterministically.
3. An underpaid application remains `payment-due`.
4. Only then may the application become `ready`.

Run the tests with:

```bash
python -m unittest discover -s tests -q
```
""",
    "AGENTS.md": """# Permit Board demo instructions

- Run `python -m unittest discover -s tests -q` after changes.
- Let the ctx hooks hydrate the active semantic scope before editing.
- When the Stop hook finds stale context, update durable meaning or explicitly
  acknowledge an implementation-only change through the supplied run command.
""",
    "permit_board/__init__.py": """\"\"\"Permit Board demo package.\"\"\"\n""",
    "permit_board/models.py": """from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ReviewStatus = Literal[\"missing-parcel\", \"payment-due\", \"ready\"]


@dataclass(frozen=True, slots=True)
class Application:
    application_id: str
    parcel_id: str | None
    declared_value_cents: int
    amount_paid_cents: int = 0
    expedited: bool = False


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    application_id: str
    status: ReviewStatus
    required_fee_cents: int
    reason: str
""",
    "permit_board/workflow.py": """from __future__ import annotations

from .models import Application, ReviewDecision
from .policy.eligibility import evaluate_application


def review_application(application: Application) -> ReviewDecision:
    \"\"\"Evaluate one application through the deterministic policy boundary.\"\"\"

    return evaluate_application(application)
""",
    "permit_board/policy/__init__.py": """\"\"\"Deterministic permit review policy.\"\"\"\n""",
    "permit_board/policy/fees.py": """from __future__ import annotations

from ..models import Application


BASE_FEE_CENTS = 10_000
EXPEDITED_SURCHARGE_CENTS = 5_000


def required_fee_cents(application: Application) -> int:
    value_component = max(0, application.declared_value_cents) // 1_000
    expedited = EXPEDITED_SURCHARGE_CENTS if application.expedited else 0
    return BASE_FEE_CENTS + value_component + expedited
""",
    "permit_board/policy/eligibility.py": """from __future__ import annotations

from ..models import Application, ReviewDecision
from .fees import required_fee_cents


def evaluate_application(application: Application) -> ReviewDecision:
    fee = required_fee_cents(application)
    if not application.parcel_id or not application.parcel_id.strip():
        return ReviewDecision(
            application.application_id,
            \"missing-parcel\",
            fee,
            \"A parcel identifier is required before staff review.\",
        )
    if application.amount_paid_cents < fee:
        return ReviewDecision(
            application.application_id,
            \"payment-due\",
            fee,
            \"The required fee must be paid before staff review.\",
        )
    return ReviewDecision(
        application.application_id,
        \"ready\",
        fee,
        \"Parcel and payment requirements are satisfied.\",
    )
""",
    "tests/__init__.py": "",
    "tests/test_workflow.py": """from __future__ import annotations

import unittest

from permit_board.models import Application
from permit_board.workflow import review_application


class ReviewWorkflowTests(unittest.TestCase):
    def test_missing_parcel_has_precedence_over_payment(self) -> None:
        for amount_paid in (0, 100_000):
            with self.subTest(amount_paid=amount_paid):
                decision = review_application(
                    Application(\"A-1\", None, 200_000_00, amount_paid_cents=amount_paid)
                )
                self.assertEqual(decision.status, \"missing-parcel\")

    def test_application_identity_is_preserved(self) -> None:
        decision = review_application(
            Application(\"EXTERNAL-42\", \"30-1234-000-0010\", 0, amount_paid_cents=10_000)
        )
        self.assertEqual(decision.application_id, \"EXTERNAL-42\")

    def test_underpaid_application_is_not_ready(self) -> None:
        decision = review_application(
            Application(\"A-2\", \"30-1234-000-0010\", 200_000_00)
        )
        self.assertEqual(decision.status, \"payment-due\")

    def test_paid_application_is_ready(self) -> None:
        decision = review_application(
            Application(
                \"A-3\",
                \"30-1234-000-0010\",
                200_000_00,
                amount_paid_cents=30_000,
            )
        )
        self.assertEqual(decision.status, \"ready\")

    def test_expedited_review_adds_a_surcharge(self) -> None:
        ordinary = review_application(
            Application(\"A-4\", \"30-1234-000-0010\", 0, amount_paid_cents=20_000)
        )
        expedited = review_application(
            Application(
                \"A-5\",
                \"30-1234-000-0010\",
                0,
                amount_paid_cents=20_000,
                expedited=True,
            )
        )
        self.assertEqual(expedited.required_fee_cents - ordinary.required_fee_cents, 5_000)


if __name__ == \"__main__\":
    unittest.main()
""",
    ".ctx/context.yaml": """version: 1

project:
  id: permit-board-demo
  name: Permit Board Demo
  aliases: [permit board]

node:
  id: root
  name: Permit review workflow
  summary: >
    Small deterministic service that moves permit applications from intake to
    staff-ready review while preserving identity and policy ordering.

artifacts:
  - path: README.md
    role: Product purpose, review order, and local verification entry point.
  - path: AGENTS.md
    role: Repository-local test command and ctx hook/reconciliation workflow.
  - path: permit_board/models.py
    role: Stable application and public review-decision contracts.
  - path: permit_board/workflow.py
    role: Public orchestration entry point into the policy boundary.
  - path: tests/test_workflow.py
    role: Representative end-to-end policy ordering and fee regression coverage.

items:
  - id: stable-application-identity
    kind: invariant
    title: Application identity remains stable
    summary: >
      application_id is the external identity carried unchanged from intake to
      every review decision.
    artifacts: [permit_board/models.py, tests/test_workflow.py]

  - id: ordered-review-pipeline
    kind: pattern
    title: Ordered deterministic review pipeline
    summary: >
      A thin workflow delegates to deterministic policy evaluation and returns
      one explicit public status with the required fee and reason.
    artifacts: [permit_board/workflow.py, permit_board/models.py, tests/test_workflow.py]
    adoption:
      mode: adapt
      requires:
        - stable input identity
        - explicit ordered eligibility states
        - deterministic side-effect-free policy functions
      adapt:
        - jurisdiction-specific fee values
        - project-specific readiness states
      verify:
        - earlier blocking states take precedence
        - an underpaid application never becomes ready

  - id: policy-is-a-semantic-boundary
    kind: decision
    title: Keep review policy behind a semantic boundary
    summary: >
      Workflow orchestration owns the public entry point while fee and
      eligibility meaning live together in the narrower policy region.
    artifacts: [permit_board/workflow.py, tests/test_workflow.py]
    reason: >
      Separating orchestration from policy makes rule ordering directly testable
      and lets an agent hydrate the governing rules only when work enters them.

tracking:
  exclude: [__pycache__/**]
""",
    "permit_board/policy/.ctx/context.yaml": """version: 1

node:
  id: policy
  name: Permit review policy
  summary: >
    Deterministic fee calculation and ordered readiness rules for one permit
    application.

artifacts:
  - path: fees.py
    role: Canonical base, value-based, and expedited fee calculation.
  - path: eligibility.py
    role: Ordered parcel, payment, and ready-state evaluation.
  - path: ../../tests/test_workflow.py
    role: Cross-boundary regression proof for precedence, payment, and surcharge behavior.

items:
  - id: missing-parcel-blocks-review
    kind: invariant
    title: Missing parcel identity blocks review first
    summary: >
      An application without a usable parcel identifier remains missing-parcel
      regardless of payment state.
    artifacts: [eligibility.py, ../../tests/test_workflow.py]

  - id: payment-precedes-readiness
    kind: invariant
    title: Required payment precedes readiness
    summary: >
      An application becomes ready only when the amount paid meets the exact
      deterministic required fee.
    artifacts: [fees.py, eligibility.py, ../../tests/test_workflow.py]

  - id: fee-components-are-explicit
    kind: decision
    title: Keep fee components explicit
    summary: >
      Base, declared-value, and expedited components are calculated as integer
      cents without hidden I/O or mutable state.
    artifacts: [fees.py, ../../tests/test_workflow.py]
    reason: >
      Explicit integer components keep outcomes reproducible and make policy
      changes visible in focused tests.
""",
}


def _first_symlink_component(path: Path) -> Path | None:
    trusted_aliases: dict[Path, Path] = {}
    if sys.platform == "darwin":
        trusted_aliases = {
            Path("/var"): Path("/private/var"),
            Path("/tmp"): Path("/private/tmp"),
            Path("/etc"): Path("/private/etc"),
        }
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise UnsafePathError(
                "demo.path-unsafe", f"cannot inspect demo target path {current}: {exc}"
            ) from exc
        if not stat.S_ISLNK(metadata.st_mode):
            continue
        expected = trusted_aliases.get(current)
        try:
            trusted = expected is not None and current.resolve(strict=True) == expected
        except OSError:
            trusted = False
        if not trusted:
            return current
    return None


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _target(path: Path) -> Path:
    candidate = absolute_lexical(path)
    if candidate.exists() or candidate.is_symlink():
        if candidate.is_symlink():
            raise UnsafePathError("demo.target-symlink", f"demo target cannot be a symlink: {candidate}")
        raise CtxError("demo.target-exists", f"demo target already exists: {candidate}", exit_code=1)
    symlink_component = _first_symlink_component(candidate.parent)
    if symlink_component is not None:
        raise UnsafePathError(
            "demo.parent-symlink",
            f"demo target cannot pass through a symlink: {symlink_component}",
        )
    try:
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CtxError(
            "demo.parent-invalid",
            f"demo target parent is unavailable: {candidate.parent}: {exc}",
            exit_code=1,
        ) from exc
    if not parent.is_dir():
        raise CtxError("demo.parent-not-directory", f"demo target parent is not a directory: {parent}", exit_code=1)
    try:
        enclosing, _identity = find_project_root(parent)
    except NotFoundError:
        pass
    else:
        raise CtxError(
            "demo.inside-project",
            f"demo target would be nested inside ctx project {enclosing}; choose a path outside it",
            exit_code=1,
        )
    return parent / candidate.name


def _write_demo(root: Path) -> None:
    for relative, content in sorted(_DEMO_FILES.items()):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")


def _publish_demo(
    source: Path,
    target: Path,
    *,
    source_fd: int | None = None,
    verify: Callable[[], None] | None = None,
) -> None:
    """Publish a prepared tree beneath an exclusively claimed directory."""

    parent_fd = os.open(target.parent, _directory_flags())
    root_fd: int | None = None
    source_root_fd = os.open(source, _directory_flags()) if source_fd is None else os.dup(source_fd)
    source_fds: list[int] = [source_root_fd]
    target_fds: list[int] = []
    created_files: list[tuple[int, str, tuple[int, int]]] = []
    created_directories: list[tuple[int, str, tuple[int, int]]] = []
    root_identity: tuple[int, int] | None = None
    failure: BaseException | None = None
    try:
        try:
            os.mkdir(target.name, mode=0o755, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise CtxError(
                "demo.target-exists",
                f"demo target appeared during creation: {target}",
                exit_code=1,
            ) from exc
        root_metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        root_fd = os.open(target.name, _directory_flags(), dir_fd=parent_fd)
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != root_identity:
            raise OSError("demo target identity changed during creation")

        def publish_directory(source_directory_fd: int, destination_fd: int) -> None:
            names = sorted(os.listdir(source_directory_fd), key=os.fsencode)
            for name in names:
                source_metadata = os.stat(
                    name,
                    dir_fd=source_directory_fd,
                    follow_symlinks=False,
                )
                if stat.S_ISDIR(source_metadata.st_mode):
                    os.mkdir(name, mode=0o755, dir_fd=destination_fd)
                    metadata = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                    identity = (metadata.st_dev, metadata.st_ino)
                    created_directories.append((destination_fd, name, identity))
                    source_child_fd = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=source_directory_fd,
                    )
                    source_fds.append(source_child_fd)
                    opened_source = os.fstat(source_child_fd)
                    if (opened_source.st_dev, opened_source.st_ino) != (
                        source_metadata.st_dev,
                        source_metadata.st_ino,
                    ):
                        raise OSError(f"prepared demo directory changed during publication: {name}")
                    target_child_fd = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=destination_fd,
                    )
                    target_fds.append(target_child_fd)
                    publish_directory(source_child_fd, target_child_fd)
                    os.fsync(target_child_fd)
                    continue
                if not stat.S_ISREG(source_metadata.st_mode):
                    raise OSError(f"bundled demo unexpectedly contains a special file: {name}")
                identity = (source_metadata.st_dev, source_metadata.st_ino)
                os.link(
                    name,
                    name,
                    src_dir_fd=source_directory_fd,
                    dst_dir_fd=destination_fd,
                    follow_symlinks=False,
                )
                linked = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                if (linked.st_dev, linked.st_ino) != identity:
                    raise OSError(f"prepared demo file changed during publication: {name}")
                created_files.append((destination_fd, name, identity))
            os.fsync(destination_fd)

        publish_directory(source_root_fd, root_fd)
        published = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != root_identity:
            raise OSError("demo target identity changed during publication")
        if verify is not None:
            verify()
        published = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != root_identity:
            raise OSError("demo target identity changed during verification")
        os.fsync(parent_fd)
    except BaseException as exc:
        failure = exc
    finally:
        if failure is not None:
            rollback_errors: list[str] = []
            for directory_fd, name, identity in reversed(created_files):
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) != identity:
                        raise OSError("file identity changed")
                    os.unlink(name, dir_fd=directory_fd)
                except OSError as exc:
                    rollback_errors.append(f"{name}: {exc}")
            for directory_fd, name, identity in reversed(created_directories):
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) != identity:
                        raise OSError("directory identity changed")
                    os.rmdir(name, dir_fd=directory_fd)
                except OSError as exc:
                    rollback_errors.append(f"{name}: {exc}")
            if root_identity is not None:
                try:
                    metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) != root_identity:
                        raise OSError("root identity changed")
                    os.rmdir(target.name, dir_fd=parent_fd)
                except OSError as exc:
                    rollback_errors.append(f"{target.name}: {exc}")
            if rollback_errors:
                failure = CtxError(
                    "demo.rollback-failed",
                    "demo publication failed and could not be safely rolled back: "
                    + "; ".join(rollback_errors),
                    exit_code=4,
                )
        for descriptor in reversed(target_fds):
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)
        for descriptor in reversed(source_fds):
            os.close(descriptor)
        os.close(parent_fd)
    if failure is not None:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise failure
        if isinstance(failure, CtxError):
            raise failure
        raise CtxError(
            "demo.write-failed",
            f"cannot publish demo project {target}: {failure}",
            exit_code=4,
        ) from failure


def create_demo(path: Path) -> DemoResult:
    """Create a complete, fresh sample project without invoking an agent."""

    target = _target(path)
    with tempfile.TemporaryDirectory(prefix=".ctx-demo-", dir=target.parent) as raw:
        temporary = Path(raw)
        project = temporary / "project"
        project.mkdir()
        prepared = project.stat()
        prepared_identity = (prepared.st_dev, prepared.st_ino)
        _write_demo(project)
        validation = validate_project(project, strict=True)
        if not validation.valid:
            first = (validation.errors or validation.strict_failures)[0]
            raise CtxError(
                "demo.invalid",
                f"bundled demo failed strict validation: {first.code}: {first.message}",
                exit_code=4,
            )
        hooks = install_codex_hooks(project=project)
        lock = seal_freshness(project)
        source_fd = os.open(project, _directory_flags())
        try:
            opened = os.fstat(source_fd)
            if (opened.st_dev, opened.st_ino) != prepared_identity:
                raise CtxError(
                    "demo.prepared-changed",
                    "prepared demo directory changed before publication",
                    exit_code=4,
                )

            def verify_published_demo() -> None:
                published_validation = validate_project(target, strict=True)
                if not published_validation.valid:
                    first = (
                        published_validation.errors
                        or published_validation.strict_failures
                    )[0]
                    raise CtxError(
                        "demo.published-invalid",
                        f"published demo failed strict validation: {first.code}: {first.message}",
                        exit_code=4,
                    )
                status = project_status(target)
                if not status.fresh:
                    raise CtxError(
                        "demo.published-not-fresh",
                        "published demo does not match its initial freshness lock",
                        exit_code=4,
                    )

            _publish_demo(
                project,
                target,
                source_fd=source_fd,
                verify=verify_published_demo,
            )
        finally:
            os.close(source_fd)
    manifests = (
        target / ".ctx" / "context.yaml",
        target / "permit_board" / "policy" / ".ctx" / "context.yaml",
    )
    return DemoResult(target, manifests, target / ".codex" / "hooks.json", target / ".ctx" / "lock.json")
