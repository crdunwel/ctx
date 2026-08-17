from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctx import reconciliation
from ctx.diagnostics import CtxError
from ctx.freshness import project_status, seal_freshness
from ctx.retrofit_agent import MAX_PROPOSED_MANIFESTS


@unittest.skipUnless(
    os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
    "reconciliation lock races require POSIX no-follow descriptors",
)
class ReconcileLockSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def project_fixture(
        self, name: str
    ) -> tuple[Path, Path, Path, bytes, str, str]:
        root = self.base / name
        context = root / ".ctx"
        context.mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        title = " ".join(part.title() for part in name.split("-"))
        original_manifest = (
            "version: 1\n"
            "project:\n"
            f"  id: {name}\n"
            f"  name: {title}\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            f"  name: {title}\n"
            "  summary: Original reviewed meaning.\n"
        )
        proposed_manifest = original_manifest.replace(
            "Original reviewed meaning", "Updated evidence-backed meaning"
        )
        manifest = context / "context.yaml"
        manifest.write_text(original_manifest, encoding="utf-8")
        lock = seal_freshness(root).path
        baseline_lock = lock.read_bytes()
        source.write_text("VALUE = 2\n", encoding="utf-8")
        return (
            root,
            source,
            manifest,
            baseline_lock,
            original_manifest,
            proposed_manifest,
        )

    def update_agent(self, proposed_manifest: str):
        def fake_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
            *,
            prompt_suffix: str = "",
        ) -> Path:
            self.assertEqual(prompt_suffix, "")
            result = work_directory / "reconcile-agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {
                                "path": ".ctx/context.yaml",
                                "content": proposed_manifest,
                            }
                        ],
                        "acknowledgements": [],
                        "summary": "Updated durable meaning.",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        return fake_agent

    def changed_valid_lock(self, baseline: bytes) -> bytes:
        payload = json.loads(baseline)
        first = next(iter(payload["nodes"].values()))
        first["source_fingerprint"] = f"sha256:{'0' * 64}"
        changed = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        self.assertNotEqual(changed, baseline)
        return changed

    def test_pre_seal_lock_snapshot_does_not_follow_symlink(self) -> None:
        root, _source, _manifest, _baseline, _original, _proposed = (
            self.project_fixture("pre-seal-lock-symlink")
        )
        before = project_status(root)
        lock = root / ".ctx" / "lock.json"
        outside = self.base / "outside-pre-seal-lock.json"
        outside_bytes = b'{"outside":"must-not-be-imported"}\n'
        outside.write_bytes(outside_bytes)
        lock.unlink()
        lock.symlink_to(outside)

        with (
            mock.patch.object(reconciliation, "project_status", return_value=before),
            mock.patch.object(reconciliation, "seal_freshness") as seal,
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation._seal_unchanged(
                    before,
                    reconciliation._root_identity(root),
                    message="project changed while sealing",
                )

        self.assertEqual(raised.exception.code, "lock.symlink")
        seal.assert_not_called()
        self.assertTrue(lock.is_symlink())
        self.assertEqual(outside.read_bytes(), outside_bytes)

    def test_publication_baseline_lock_snapshot_does_not_follow_symlink(self) -> None:
        root, _source, manifest, _baseline, original, proposed = (
            self.project_fixture("publication-lock-symlink")
        )
        lock = root / ".ctx" / "lock.json"
        outside = self.base / "outside-publication-lock.json"
        outside_bytes = b'{"outside":"publication-canary"}\n'
        outside.write_bytes(outside_bytes)
        read_snapshot = reconciliation._read_reconcile_lock_snapshot

        def swap_at_publication_baseline(
            project_root: Path,
            expected_identity: tuple[int, int],
            *,
            phase: str,
        ) -> bytes | None:
            self.assertIn("publication", phase)
            lock.unlink()
            lock.symlink_to(outside)
            return read_snapshot(
                project_root,
                expected_identity,
                phase=phase,
            )

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=self.update_agent(proposed),
            ),
            mock.patch.object(
                reconciliation,
                "_read_reconcile_lock_snapshot",
                side_effect=swap_at_publication_baseline,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "lock.symlink")
        self.assertEqual(manifest.read_text(encoding="utf-8"), original)
        self.assertTrue(lock.is_symlink())
        self.assertEqual(outside.read_bytes(), outside_bytes)

    def test_publication_seal_uses_cas_and_rolls_back_manifest(self) -> None:
        for mode in ("replacement", "symlink"):
            with self.subTest(mode=mode):
                root, _source, manifest, baseline, original, proposed = (
                    self.project_fixture(f"publication-cas-{mode}")
                )
                lock = root / ".ctx" / "lock.json"
                concurrent = self.changed_valid_lock(baseline)
                outside = self.base / f"outside-publication-cas-{mode}.json"
                outside.write_bytes(concurrent)
                real_seal = seal_freshness
                observed_previous: list[bytes | None] = []

                def change_before_seal(path: Path, **kwargs: object) -> object:
                    observed_previous.append(kwargs.get("expected_previous"))
                    if mode == "replacement":
                        lock.write_bytes(concurrent)
                    else:
                        lock.unlink()
                        lock.symlink_to(outside)
                    return real_seal(path, **kwargs)

                with (
                    mock.patch.object(
                        reconciliation,
                        "_run_codex",
                        side_effect=self.update_agent(proposed),
                    ),
                    mock.patch.object(
                        reconciliation,
                        "seal_freshness",
                        side_effect=change_before_seal,
                    ),
                ):
                    with self.assertRaises(CtxError) as raised:
                        reconciliation.reconcile_project(root)

                if mode == "replacement":
                    self.assertEqual(
                        raised.exception.code,
                        "reconcile.project-changed",
                    )
                else:
                    self.assertIn(
                        raised.exception.code,
                        {"lock.symlink", "lock.validation-failed"},
                    )
                self.assertEqual(observed_previous, [baseline])
                self.assertEqual(manifest.read_text(encoding="utf-8"), original)
                if mode == "replacement":
                    self.assertEqual(lock.read_bytes(), concurrent)
                else:
                    self.assertTrue(lock.is_symlink())
                    self.assertEqual(outside.read_bytes(), concurrent)

    def test_post_seal_rollback_cas_preserves_concurrent_lock(self) -> None:
        for mode in ("replacement", "symlink"):
            with self.subTest(mode=mode):
                root, source, manifest, baseline, original, proposed = (
                    self.project_fixture(f"post-seal-cas-{mode}")
                )
                lock = root / ".ctx" / "lock.json"
                concurrent = self.changed_valid_lock(baseline)
                outside = self.base / f"outside-post-seal-cas-{mode}.json"
                outside.write_bytes(concurrent)
                real_seal = seal_freshness
                observed_previous: list[bytes | None] = []

                def seal_then_change(path: Path, **kwargs: object) -> object:
                    observed_previous.append(kwargs.get("expected_previous"))
                    result = real_seal(path, **kwargs)
                    if mode == "replacement":
                        result.path.write_bytes(concurrent)
                    else:
                        result.path.unlink()
                        result.path.symlink_to(outside)
                    return result

                with (
                    mock.patch.object(
                        reconciliation,
                        "_run_codex",
                        side_effect=self.update_agent(proposed),
                    ),
                    mock.patch.object(
                        reconciliation,
                        "seal_freshness",
                        side_effect=seal_then_change,
                    ),
                ):
                    with self.assertRaises(CtxError) as raised:
                        reconciliation.reconcile_project(root)

                if mode == "replacement":
                    self.assertEqual(raised.exception.code, "lock.rollback-failed")
                else:
                    self.assertIn(
                        raised.exception.code,
                        {"lock.rollback-failed", "lock.symlink"},
                    )
                self.assertEqual(observed_previous, [baseline])
                self.assertEqual(manifest.read_text(encoding="utf-8"), original)
                self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
                if mode == "replacement":
                    self.assertEqual(lock.read_bytes(), concurrent)
                else:
                    self.assertTrue(lock.is_symlink())
                    self.assertEqual(outside.read_bytes(), concurrent)

    def test_acknowledgement_requires_exact_post_seal_lock_bytes(self) -> None:
        root, _source, manifest, baseline, original, _proposed = (
            self.project_fixture("acknowledgement-exact-sealed-lock")
        )
        lock = root / ".ctx" / "lock.json"
        real_seal = seal_freshness
        alternate: list[bytes] = []
        observed_previous: list[bytes | None] = []

        def seal_then_reserialize(path: Path, **kwargs: object) -> object:
            observed_previous.append(kwargs.get("expected_previous"))
            result = real_seal(path, **kwargs)
            replacement = (
                json.dumps(
                    json.loads(result.content),
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            self.assertNotEqual(replacement, result.content)
            result.path.write_bytes(replacement)
            alternate.append(replacement)
            return result

        with mock.patch.object(
            reconciliation,
            "seal_freshness",
            side_effect=seal_then_reserialize,
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(
                    root,
                    acknowledge_reason="Reviewed as implementation-only.",
                )

        self.assertEqual(raised.exception.code, "lock.rollback-failed")
        self.assertEqual(observed_previous, [baseline])
        self.assertEqual(lock.read_bytes(), alternate[0])
        self.assertTrue(project_status(root).fresh)
        self.assertEqual(manifest.read_text(encoding="utf-8"), original)

    def test_final_inventory_manifest_race_cannot_return_success(self) -> None:
        root, source, manifest, baseline, _original, proposed = self.project_fixture(
            "final-inventory-manifest-race"
        )
        concurrent = proposed.replace(
            "Updated evidence-backed meaning",
            "Concurrent unreviewed meaning",
        )
        fingerprint = reconciliation._fingerprint_eligible_evidence
        excluded_fingerprints = 0

        def mutate_after_final_fingerprint(
            inventory: object,
            root_fd: int,
            *,
            exclude_paths: frozenset[str] = frozenset(),
        ) -> str:
            nonlocal excluded_fingerprints
            result = fingerprint(
                inventory,  # type: ignore[arg-type]
                root_fd,
                exclude_paths=exclude_paths,
            )
            if ".ctx/context.yaml" in exclude_paths:
                excluded_fingerprints += 1
                if excluded_fingerprints == 2:
                    manifest.write_text(concurrent, encoding="utf-8")
            return result

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=self.update_agent(proposed),
            ),
            mock.patch.object(
                reconciliation,
                "_fingerprint_eligible_evidence",
                side_effect=mutate_after_final_fingerprint,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(excluded_fingerprints, 2)
        self.assertEqual(raised.exception.code, "reconcile.rollback-failed")
        self.assertEqual(manifest.read_text(encoding="utf-8"), concurrent)
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
        self.assertEqual((root / ".ctx" / "lock.json").read_bytes(), baseline)
        self.assertFalse(project_status(root).fresh)

    def test_preflight_reuses_one_bounded_file_per_attempt(self) -> None:
        root, _source, _manifest, _baseline, _original, _proposed = (
            self.project_fixture("bounded-preflight-files")
        )
        status = project_status(root)
        manifests = [
            {
                "path": None,
                "content": "version: 1\nnode:\n  id: root\n  name: Tiny\n",
            }
            for _index in range(MAX_PROPOSED_MANIFESTS + 17)
        ]

        for attempt in ("attempt-1", "attempt-2"):
            work = self.base / attempt
            work.mkdir()
            with self.assertRaises(CtxError) as raised:
                reconciliation._prepare(
                    status,
                    manifests,
                    [],
                    work,
                    output_summary="bounded preflight",
                )
            self.assertEqual(raised.exception.code, "reconcile.agent-output-invalid")
            self.assertEqual(
                [path.name for path in work.iterdir()],
                ["preflight-reconcile.yaml"],
            )


if __name__ == "__main__":
    unittest.main()
