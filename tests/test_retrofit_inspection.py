from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from functools import partial
from pathlib import Path
from unittest import mock

from ctx import freshness, lifecycle, reconciliation, retrofit_agent
from ctx.diagnostics import CtxError
from ctx.freshness import project_status, seal_freshness
from ctx.retrofit import _open_directory_no_follow, inventory_repository
from ctx.validation import validate_project


@unittest.skipUnless(
    os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
    "guarded inspection snapshots require POSIX no-follow descriptors",
)
class RetrofitInspectionCorpusTests(unittest.TestCase):
    """Behavioral regressions for the bounded automated-inspection corpus."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def build_snapshot(
        self,
        root: Path,
        destination: Path,
        *,
        byte_budget: int,
    ) -> object:
        inventory = inventory_repository(root)
        self.assertFalse(inventory.truncated, inventory.partial_reasons)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        try:
            with mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_BYTES", byte_budget
            ):
                return retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, destination
                )
        finally:
            os.close(root_fd)

    def fingerprint(self, result: object) -> str:
        value = (
            result
            if isinstance(result, str)
            else getattr(result, "evidence_fingerprint", None)
        )
        self.assertIsInstance(value, str)
        assert isinstance(value, str)
        self.assertRegex(value, r"^sha256:[0-9a-f]{64}$")
        return value

    def copied_project_paths(
        self, snapshot: Path, eligible_paths: set[str]
    ) -> set[str]:
        return {
            path.relative_to(snapshot).as_posix()
            for path in snapshot.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.relative_to(snapshot).as_posix() in eligible_paths
        }

    def catalog_bytes(
        self, snapshot: Path, eligible_paths: set[str]
    ) -> tuple[tuple[str, bytes], ...]:
        generated: list[tuple[str, bytes]] = []
        for path in sorted(snapshot.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(snapshot).as_posix()
            if relative == ".ctx-retrofit-root" or relative in eligible_paths:
                continue
            generated.append((relative, path.read_bytes()))
        self.assertTrue(
            generated,
            "a bounded catalog must describe eligible files omitted from the corpus",
        )
        return tuple(generated)

    def jpeg(self, discriminator: int, *, size: int = 64) -> bytes:
        self.assertGreaterEqual(size, 8)
        return b"\xff\xd8\xff\xe0" + bytes([discriminator]) * (size - 6) + b"\xff\xd9"

    def root_review_envelope(self, inventory: object) -> dict[str, object]:
        eligible = tuple(getattr(inventory, "eligible_files"))
        coverage: list[dict[str, object]] = []
        for area in retrofit_agent._review_inventory_areas(inventory):
            evidence = next(
                path
                for path in eligible
                if retrofit_agent._evidence_is_under_area(path, area)
            )
            coverage.append(
                {
                    "area": area,
                    "disposition": "node" if area == "." else "ancestor-covered",
                    "scope": ".ctx/context.yaml",
                    "evidence": [evidence],
                    "summary": "The proposed root scope covers this bounded area.",
                }
            )
        return {"coverage": coverage, "conflicts": []}

    def test_aggregate_media_over_budget_uses_a_catalog_and_fair_sample(self) -> None:
        root = self.base / "media-project"
        root.mkdir()
        source = b"def run():\n    return 'ok'\n"
        (root / "app.py").write_bytes(source)
        media_paths: list[str] = []
        discriminator = 1
        for area in ("alpha", "middle", "zulu"):
            directory = root / area / "photos"
            directory.mkdir(parents=True)
            for index in range(2):
                relative = f"{area}/photos/image-{index}.jpeg"
                (root / relative).write_bytes(self.jpeg(discriminator))
                media_paths.append(relative)
                discriminator += 1

        eligible = {"app.py", *media_paths}
        budget = len(source) + 3 * 64
        first_snapshot = self.base / "snapshot-one"
        first_result = self.build_snapshot(
            root, first_snapshot, byte_budget=budget
        )
        first_paths = self.copied_project_paths(first_snapshot, eligible)
        selected_media = first_paths.intersection(media_paths)

        self.assertIn("app.py", first_paths)
        self.assertGreater(len(selected_media), 0)
        self.assertLess(len(selected_media), len(media_paths))
        self.assertEqual(
            {Path(path).parts[0] for path in selected_media},
            {"alpha", "middle", "zulu"},
            "a lexically early noisy area must not starve later project areas",
        )
        copied_bytes = sum((root / path).stat().st_size for path in first_paths)
        self.assertLessEqual(copied_bytes, budget)

        first_catalog = self.catalog_bytes(first_snapshot, eligible)
        catalog_text = b"\n".join(content for _path, content in first_catalog).decode(
            "utf-8", errors="replace"
        )
        for path in media_paths:
            self.assertIn(path, catalog_text)

        second_snapshot = self.base / "snapshot-two"
        second_result = self.build_snapshot(
            root, second_snapshot, byte_budget=budget
        )
        self.assertEqual(
            self.copied_project_paths(second_snapshot, eligible), first_paths
        )
        self.assertEqual(
            self.catalog_bytes(second_snapshot, eligible), first_catalog
        )
        self.assertEqual(
            self.fingerprint(second_result), self.fingerprint(first_result)
        )

    def test_exact_duplicates_do_not_displace_distinct_area_evidence(self) -> None:
        root = self.base / "duplicate-project"
        (root / "alpha").mkdir(parents=True)
        (root / "omega").mkdir()
        source = b"ENTRY = True\n"
        (root / "app.py").write_bytes(source)
        duplicate = self.jpeg(11)
        distinct = self.jpeg(29)
        (root / "alpha" / "first.jpeg").write_bytes(duplicate)
        (root / "alpha" / "second.jpeg").write_bytes(duplicate)
        (root / "omega" / "distinct.jpeg").write_bytes(distinct)
        media_paths = {
            "alpha/first.jpeg",
            "alpha/second.jpeg",
            "omega/distinct.jpeg",
        }
        eligible = {"app.py", *media_paths}

        snapshot = self.base / "duplicate-snapshot"
        result = self.build_snapshot(
            root,
            snapshot,
            byte_budget=len(source) + len(duplicate) + len(distinct),
        )
        copied = self.copied_project_paths(snapshot, eligible)
        selected_media = copied.intersection(media_paths)

        self.assertIn("omega/distinct.jpeg", selected_media)
        self.assertEqual(
            len(selected_media.intersection({"alpha/first.jpeg", "alpha/second.jpeg"})),
            1,
        )
        self.assertEqual(len(selected_media), 2)
        catalog_text = b"\n".join(
            content for _path, content in self.catalog_bytes(snapshot, eligible)
        ).decode("utf-8", errors="replace")
        for path in media_paths:
            self.assertIn(path, catalog_text)
        self.fingerprint(result)

    def test_presentation_only_area_truncation_does_not_block_inspection(self) -> None:
        root = self.base / "many-areas-project"
        root.mkdir()
        for index in range(27):
            area = root / f"area-{index:02d}"
            area.mkdir()
            (area / "main.py").write_text(
                f"AREA = {index}\n", encoding="utf-8"
            )
        inventory = inventory_repository(root)
        self.assertTrue(inventory.truncated)
        self.assertEqual(inventory.partial_reasons, ("area-output-limit",))
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        try:
            inspection = retrofit_agent._build_filtered_snapshot(
                inventory,
                root_fd,
                self.base / "many-areas-snapshot",
            )
        finally:
            os.close(root_fd)

        self.assertEqual(inspection.copied_files, 27)

    def test_evidence_scan_truncation_still_blocks_automated_inspection(self) -> None:
        root = self.base / "partial-evidence-project"
        root.mkdir()
        for index in range(3):
            (root / f"source-{index}.py").write_text(
                f"VALUE = {index}\n", encoding="utf-8"
            )
        with mock.patch("ctx.retrofit.MAX_FILES", 1):
            inventory = inventory_repository(root)
        self.assertTrue(inventory.truncated)
        self.assertIn("file-limit", inventory.partial_reasons)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        try:
            with self.assertRaises(CtxError) as raised:
                retrofit_agent._build_filtered_snapshot(
                    inventory,
                    root_fd,
                    self.base / "partial-evidence-snapshot",
                )
        finally:
            os.close(root_fd)
        self.assertEqual(raised.exception.code, "retrofit.snapshot-incomplete")

    def test_oversized_inspectable_text_fails_with_manual_scope_fallback(self) -> None:
        root = self.base / "oversized-source"
        root.mkdir()
        source = root / "core.py"
        source.write_text("VALUE = 'inspectable'\n" * 8, encoding="utf-8")
        budget = source.stat().st_size - 1

        with self.assertRaises(CtxError) as raised:
            self.build_snapshot(
                root, self.base / "oversized-snapshot", byte_budget=budget
            )

        self.assertEqual(raised.exception.code, "retrofit.snapshot-failed")
        self.assertEqual(raised.exception.exit_code, 4)
        self.assertIn("core.py", raised.exception.message)
        self.assertIn("ctx retrofit prompt", raised.exception.message)
        self.assertIn("manually scoped", raised.exception.message)

    def test_omitted_media_content_is_covered_by_the_full_fingerprint(self) -> None:
        root = self.base / "fingerprint-project"
        (root / "photos").mkdir(parents=True)
        source = b"PUBLIC = True\n"
        (root / "app.py").write_bytes(source)
        media_paths: list[str] = []
        for index in range(5):
            relative = f"photos/image-{index}.jpeg"
            (root / relative).write_bytes(self.jpeg(index + 40))
            media_paths.append(relative)
        eligible = {"app.py", *media_paths}
        budget = len(source) + 2 * 64

        first_snapshot = self.base / "fingerprint-snapshot-one"
        first_result = self.build_snapshot(
            root, first_snapshot, byte_budget=budget
        )
        first_copied = self.copied_project_paths(first_snapshot, eligible)
        omitted = sorted(set(media_paths) - first_copied)
        self.assertTrue(omitted)
        changed_path = omitted[0]
        original_size = (root / changed_path).stat().st_size
        (root / changed_path).write_bytes(self.jpeg(99, size=original_size))

        second_snapshot = self.base / "fingerprint-snapshot-two"
        second_result = self.build_snapshot(
            root, second_snapshot, byte_budget=budget
        )
        second_copied = self.copied_project_paths(second_snapshot, eligible)
        self.assertNotIn(changed_path, second_copied)
        self.assertLessEqual(
            sum((root / path).stat().st_size for path in second_copied), budget
        )
        self.assertNotEqual(
            self.fingerprint(first_result), self.fingerprint(second_result)
        )

    def test_scoped_inspection_limits_visible_files_but_keeps_full_fingerprint(self) -> None:
        root = self.base / "scoped-inspection-project"
        (root / "alpha").mkdir(parents=True)
        (root / "beta").mkdir()
        (root / "README.md").write_text("Repository instructions.\n", encoding="utf-8")
        (root / "alpha" / "main.py").write_text("ALPHA = True\n", encoding="utf-8")
        (root / "beta" / "main.py").write_text("BETA = True\n", encoding="utf-8")
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        try:
            scoped = retrofit_agent._build_filtered_snapshot(
                inventory,
                root_fd,
                self.base / "scoped-inspection-snapshot",
                inspection_paths=frozenset({"alpha/main.py"}),
            )
            expected_fingerprint = retrofit_agent._fingerprint_eligible_evidence(
                inventory, root_fd
            )
            required = retrofit_agent._build_filtered_snapshot(
                inventory,
                root_fd,
                self.base / "required-inspection-snapshot",
                inspection_paths=frozenset({"alpha/main.py"}),
                required_paths=frozenset({"beta/main.py"}),
            )
        finally:
            os.close(root_fd)

        self.assertEqual(scoped.evidence_fingerprint, expected_fingerprint)
        self.assertIn("README.md", scoped.copied_paths)
        self.assertIn("alpha/main.py", scoped.copied_paths)
        self.assertNotIn("beta/main.py", scoped.copied_paths)
        catalog = json.loads(
            (
                self.base
                / "scoped-inspection-snapshot"
                / retrofit_agent.INSPECTION_CATALOG_PATH
            ).read_text(encoding="utf-8")
        )
        beta = next(item for item in catalog["files"] if item["path"] == "beta/main.py")
        self.assertEqual(beta["representation"], "catalog-only")
        self.assertIn("beta/main.py", required.copied_paths)
        self.assertEqual(required.evidence_fingerprint, expected_fingerprint)

    def test_full_fingerprint_keeps_the_saved_plan_canonical_format(self) -> None:
        root = self.base / "canonical-fingerprint-project"
        (root / "photos").mkdir(parents=True)
        (root / "app.py").write_text("READY = True\n", encoding="utf-8")
        (root / "photos" / "source.jpeg").write_bytes(self.jpeg(61))
        inventory = inventory_repository(root)
        snapshot = self.base / "canonical-fingerprint-snapshot"
        result = self.build_snapshot(root, snapshot, byte_budget=32)

        expected = hashlib.sha256()
        paths = sorted(
            set(inventory.eligible_files) | set(inventory.all_context_manifests)
        )
        for relative in paths:
            source = inventory.root / relative
            data = source.read_bytes()
            path_bytes = relative.encode("utf-8")
            expected.update(len(path_bytes).to_bytes(8, "big"))
            expected.update(path_bytes)
            expected.update(stat.S_IMODE(source.stat().st_mode).to_bytes(4, "big"))
            expected.update(len(data).to_bytes(8, "big"))
            expected.update(hashlib.sha256(data).digest())

        self.assertEqual(
            self.fingerprint(result), f"sha256:{expected.hexdigest()}"
        )

    def test_large_structured_data_uses_a_labeled_preview(self) -> None:
        root = self.base / "structured-project"
        root.mkdir()
        source = root / "records.jsonl"
        source.write_text(
            "".join(f'{{"id": {index}, "name": "record-{index}"}}\n' for index in range(20)),
            encoding="utf-8",
        )
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "structured-snapshot"
        try:
            with (
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_STRUCTURED_FILE_BYTES", 32
                ),
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_PREVIEW_FILE_BYTES", 96
                ),
            ):
                result = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)

        self.assertNotIn("records.jsonl", result.copied_paths)
        self.assertFalse((snapshot / "records.jsonl").exists())
        previews = sorted((snapshot / retrofit_agent.INSPECTION_PREVIEW_DIRECTORY).iterdir())
        self.assertEqual(len(previews), 1)
        preview = previews[0].read_text(encoding="utf-8")
        self.assertIn("generated file is not authoritative source", preview)
        self.assertIn("source path: records.jsonl", preview)
        catalog = json.loads(
            (snapshot / retrofit_agent.INSPECTION_CATALOG_PATH).read_text(
                encoding="utf-8"
            )
        )
        entry = next(value for value in catalog["files"] if value["path"] == "records.jsonl")
        self.assertEqual(entry["representation"], "preview")
        self.assertLessEqual(
            result.copied_bytes + result.preview_bytes,
            retrofit_agent.MAX_INSPECTION_BYTES,
        )

    def test_large_nonmandatory_text_is_previewed_without_starving_source(self) -> None:
        root = self.base / "large-text-project"
        root.mkdir()
        (root / "large.py").write_text("VALUE = 1\n" * 64, encoding="utf-8")
        (root / "main.py").write_text("READY = True\n", encoding="utf-8")
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "large-text-snapshot"
        try:
            with (
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_TEXT_FILE_BYTES", 64
                ),
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_PREVIEW_FILE_BYTES", 96
                ),
                mock.patch.object(retrofit_agent, "MAX_INSPECTION_BYTES", 1_024),
            ):
                result = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)

        self.assertIn("main.py", result.copied_paths)
        self.assertNotIn("large.py", result.copied_paths)
        self.assertFalse((snapshot / "large.py").exists())
        self.assertEqual(result.preview_files, 1)
        self.assertLessEqual(result.copied_bytes + result.preview_bytes, 1_024)

    def test_long_structured_name_has_a_bounded_generated_preview_name(self) -> None:
        root = self.base / "long-preview-project"
        root.mkdir()
        name = "r" * 180 + ".json"
        source = root / name
        source.write_text(
            json.dumps({"records": ["value" * 100]}) + "\n",
            encoding="utf-8",
        )
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "long-preview-snapshot"
        try:
            with (
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_STRUCTURED_FILE_BYTES", 32
                ),
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_PREVIEW_FILE_BYTES", 96
                ),
                mock.patch.object(retrofit_agent, "MAX_INSPECTION_BYTES", 1_024),
            ):
                result = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)

        previews = list(
            (snapshot / retrofit_agent.INSPECTION_PREVIEW_DIRECTORY).iterdir()
        )
        self.assertEqual(len(previews), 1)
        self.assertLessEqual(len(previews[0].name.encode("utf-8")), 255)
        self.assertLessEqual(result.copied_bytes + result.preview_bytes, 1_024)

    def test_invalid_utf8_structured_file_is_opaque_not_an_expanding_preview(
        self,
    ) -> None:
        root = self.base / "invalid-structured-project"
        root.mkdir()
        source = root / "records.json"
        source.write_bytes(b"\xff" * 512)
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "invalid-structured-snapshot"
        try:
            with (
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_STRUCTURED_FILE_BYTES", 32
                ),
                mock.patch.object(retrofit_agent, "MAX_INSPECTION_BYTES", 128),
            ):
                result = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)

        self.assertEqual(result.preview_files, 0)
        self.assertFalse((snapshot / "records.json").exists())
        catalog = json.loads(
            (snapshot / retrofit_agent.INSPECTION_CATALOG_PATH).read_text()
        )
        entry = next(
            value for value in catalog["files"] if value["path"] == "records.json"
        )
        self.assertEqual(entry["kind"], "opaque")
        self.assertEqual(entry["representation"], "catalog-only")

    def test_mixed_priorities_still_cover_distinct_project_areas(self) -> None:
        root = self.base / "mixed-priority-project"
        (root / "packages" / "alpha" / "src").mkdir(parents=True)
        (root / "packages" / "zulu" / "tests").mkdir(parents=True)
        for index in range(4):
            (
                root / "packages" / "alpha" / "src" / f"module-{index}.py"
            ).write_text(
                f"ALPHA_{index} = {index}\n".ljust(64, "#"),
                encoding="utf-8",
            )
        test_source = "ZULU_TEST = True\n".ljust(64, "#")
        (root / "packages" / "zulu" / "tests" / "test_feature.py").write_text(
            test_source,
            encoding="utf-8",
        )

        snapshot = self.base / "mixed-priority-snapshot"
        result = self.build_snapshot(root, snapshot, byte_budget=128)

        self.assertIn(
            "packages/zulu/tests/test_feature.py", result.copied_paths
        )
        self.assertEqual(result.copied_files, 2)

    def test_single_app_layers_are_distinct_inspection_buckets(self) -> None:
        root = self.base / "single-app-layer-project"
        for directory in (
            "VetInventory/Application",
            "VetInventory/Features",
            "VetInventoryTests",
        ):
            (root / directory).mkdir(parents=True)
        for index in range(4):
            (root / "VetInventory" / "Application" / f"Service{index}.swift").write_text(
                f"let service{index} = {index}\n".ljust(64, "/"),
                encoding="utf-8",
            )
        (root / "VetInventory" / "Features" / "CountHomeView.swift").write_text(
            "struct CountHomeView {}\n".ljust(64, "/"),
            encoding="utf-8",
        )
        (root / "VetInventoryTests" / "InventoryRepositoryTests.swift").write_text(
            "final class InventoryRepositoryTests {}\n".ljust(64, "/"),
            encoding="utf-8",
        )

        result = self.build_snapshot(
            root,
            self.base / "single-app-layer-snapshot",
            byte_budget=192,
        )

        self.assertEqual(result.copied_files, 3)
        self.assertTrue(
            any(path.startswith("VetInventory/Application/") for path in result.copied_paths)
        )
        self.assertIn(
            "VetInventory/Features/CountHomeView.swift", result.copied_paths
        )
        self.assertIn(
            "VetInventoryTests/InventoryRepositoryTests.swift",
            result.copied_paths,
        )

    def test_review_areas_do_not_inherit_presentation_truncation(self) -> None:
        root = self.base / "coverage-area-project"
        for index in range(30):
            directory = root / f"area-{index:02d}"
            directory.mkdir(parents=True)
            (directory / "source.py").write_text("READY = True\n", encoding="utf-8")
        nested = root / "zapp" / "Features"
        nested.mkdir(parents=True)
        (nested / "screen.py").write_text("SCREEN = True\n", encoding="utf-8")

        inventory = inventory_repository(root)

        self.assertIn("area-output-limit", inventory.partial_reasons)
        self.assertIn(
            "zapp/Features", retrofit_agent._review_inventory_areas(inventory)
        )

        with mock.patch.object(retrofit_agent, "MAX_COVERAGE_AREAS", 2):
            with self.assertRaisesRegex(CtxError, "automated area limit"):
                retrofit_agent._review_inventory_areas(inventory)

    def test_review_envelope_accepts_exact_hostile_inventory_paths(self) -> None:
        root = self.base / "hostile-review-path-project"
        hostile_area = "unsafe\narea"
        directory = root / hostile_area
        directory.mkdir(parents=True)
        hostile_path = f"{hostile_area}/bad\\name.py"
        (directory / "bad\\name.py").write_text("READY = True\n", encoding="utf-8")
        inventory = inventory_repository(root)
        areas = retrofit_agent._review_inventory_areas(inventory)

        coverage, conflicts = retrofit_agent._parse_review_envelope(
            [
                {
                    "area": hostile_area,
                    "disposition": "unresolved",
                    "scope": None,
                    "evidence": [hostile_path],
                    "summary": "The hostile path is fingerprinted but needs review.",
                }
            ],
            [],
            code="test.invalid",
            allowed_areas=areas,
            allowed_evidence=frozenset(inventory.eligible_files),
            inspectable_evidence=frozenset(),
            allowed_scopes=frozenset(),
        )

        self.assertEqual(coverage[0].area, hostile_area)
        self.assertEqual(coverage[0].evidence, (hostile_path,))
        self.assertEqual(conflicts, ())

    def test_root_review_area_accepts_nested_project_evidence(self) -> None:
        coverage, conflicts = retrofit_agent._parse_review_envelope(
            [
                {
                    "area": ".",
                    "disposition": "node",
                    "scope": ".ctx/context.yaml",
                    "evidence": ["src/application.py"],
                    "summary": "The project root is supported by nested source evidence.",
                }
            ],
            [],
            code="test.invalid",
            allowed_areas=(".",),
            allowed_evidence=frozenset({"src/application.py"}),
            inspectable_evidence=frozenset({"src/application.py"}),
            allowed_scopes=frozenset({".ctx/context.yaml"}),
        )

        self.assertEqual(coverage[0].area, ".")
        self.assertEqual(coverage[0].evidence, ("src/application.py",))
        self.assertEqual(conflicts, ())

    def test_json_media_relationships_complete_a_source_output_pair(self) -> None:
        root = self.base / "relationship-project"
        (root / "public" / "data").mkdir(parents=True)
        (root / "public" / "images" / "businesses").mkdir(parents=True)
        (root / "raw-photos").mkdir()
        records: list[dict[str, object]] = []
        for index in range(2):
            raw_name = f"source-{index}.jpeg"
            output_name = f"business-{index}.webp"
            (root / "raw-photos" / raw_name).write_bytes(self.jpeg(90 + index))
            (root / "public" / "images" / "businesses" / output_name).write_bytes(
                self.jpeg(100 + index)
            )
            records.append(
                {
                    "id": f"business-{index}",
                    "sourcePhotos": [raw_name],
                    "photos": [f"/images/businesses/{output_name}"],
                }
            )
        ledger = json.dumps(records, sort_keys=True) + "\n"
        (root / "public" / "data" / "businesses.json").write_text(
            ledger,
            encoding="utf-8",
        )
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "relationship-snapshot"
        try:
            with (
                mock.patch.object(retrofit_agent, "MAX_INSPECTION_BYTES", 4_096),
                mock.patch.object(retrofit_agent, "MAX_INSPECTION_MEDIA_BYTES", 192),
                mock.patch.object(
                    retrofit_agent,
                    "MAX_INSPECTION_MEDIA_RELATIONSHIP_BYTES",
                    128,
                ),
                mock.patch.object(
                    retrofit_agent, "MAX_INSPECTION_MEDIA_RELATIONSHIP_PAIRS", 1
                ),
            ):
                result = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)

        catalog = json.loads(
            (snapshot / retrofit_agent.INSPECTION_CATALOG_PATH).read_text(
                encoding="utf-8"
            )
        )
        complete = [
            value
            for value in catalog["relationships"]
            if value["complete_pair_available"]
        ]
        expected = {
            (
                "public/data/businesses.json",
                (
                    f"raw-photos/source-{index}.jpeg",
                    f"public/images/businesses/business-{index}.webp",
                ),
            )
            for index in range(2)
        }
        actual = {
            (value["evidence"], tuple(value["paths"]))
            for value in catalog["relationships"]
        }
        self.assertEqual(actual, expected)
        self.assertEqual(len(complete), 1)
        self.assertTrue(set(complete[0]["paths"]).issubset(result.copied_paths))

    def test_relationship_scan_is_bounded_for_deep_json(self) -> None:
        root = self.base / "deep-relationship-project"
        (root / "public" / "data").mkdir(parents=True)
        (root / "public" / "images" / "businesses").mkdir(parents=True)
        (root / "raw-photos").mkdir()
        for name, discriminator in (("near", 110), ("far", 111)):
            (root / "raw-photos" / f"{name}.jpeg").write_bytes(
                self.jpeg(discriminator)
            )
            (root / "public" / "images" / "businesses" / f"{name}.webp").write_bytes(
                b"RIFF" + bytes([discriminator]) * 32
            )
        (root / "public" / "data" / "deep.json").write_text(
            json.dumps(
                {
                    "sourcePhotos": ["near.jpeg"],
                    "photos": ["/images/businesses/near.webp"],
                    "nested": {
                        "nested": {
                            "sourcePhotos": ["far.jpeg"],
                            "photos": ["/images/businesses/far.webp"],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        snapshot = self.base / "deep-relationship-snapshot"
        with (
            mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_REFERENCE_DEPTH", 1
            ),
            mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_REFERENCE_NODES", 2
            ),
        ):
            result = self.build_snapshot(root, snapshot, byte_budget=4_096)

        self.assertIn("public/data/deep.json", result.copied_paths)
        catalog = json.loads(
            (snapshot / retrofit_agent.INSPECTION_CATALOG_PATH).read_text()
        )
        actual = {
            tuple(value["paths"])
            for value in catalog["relationships"]
        }
        self.assertIn(
            (
                "raw-photos/near.jpeg",
                "public/images/businesses/near.webp",
            ),
            actual,
        )
        self.assertNotIn(
            (
                "raw-photos/far.jpeg",
                "public/images/businesses/far.webp",
            ),
            actual,
        )

    def test_protected_top_level_content_is_hash_only(self) -> None:
        root = self.base / "protected-project"
        (root / "private").mkdir(parents=True)
        canary = "OWNER_ONLY_CANARY_5d283b\n"
        (root / "private" / "notes.txt").write_text(canary, encoding="utf-8")
        (root / "app.py").write_text("READY = True\n", encoding="utf-8")
        snapshot = self.base / "protected-snapshot"

        result = self.build_snapshot(root, snapshot, byte_budget=4_096)

        self.assertNotIn("private/notes.txt", result.copied_paths)
        catalog_raw = (snapshot / retrofit_agent.INSPECTION_CATALOG_PATH).read_text(
            encoding="utf-8"
        )
        self.assertIn("private/notes.txt", catalog_raw)
        self.assertNotIn(canary.strip(), catalog_raw)
        self.assertNotIn(
            canary.strip(),
            "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in snapshot.rglob("*")
                if path.is_file()
            ),
        )

    def test_validation_only_placeholders_support_omitted_artifacts(self) -> None:
        root = self.base / "artifact-project"
        (root / ".ctx").mkdir(parents=True)
        (root / "photos").mkdir()
        (root / "photos" / "source.jpeg").write_bytes(self.jpeg(71))
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: artifact-project\n"
            "  name: Artifact Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Artifact Project\n"
            "artifacts:\n"
            "  - path: photos/source.jpeg\n"
            "    role: Canonical visual source.\n",
            encoding="utf-8",
        )
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot_root = self.base / "artifact-snapshot"
        try:
            with mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_MEDIA_BYTES", 0
            ):
                inspection = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot_root
                )
        finally:
            os.close(root_fd)

        omitted = snapshot_root / "photos" / "source.jpeg"
        self.assertFalse(omitted.exists())
        retrofit_agent._materialize_validation_placeholders(
            snapshot_root, inspection
        )
        self.assertEqual(omitted.read_bytes(), b"")
        self.assertTrue(validate_project(snapshot_root, strict=True).valid)

    def test_validation_placeholder_rejects_an_appearing_symlink(self) -> None:
        root = self.base / "placeholder-race-project"
        (root / "photos").mkdir(parents=True)
        (root / "photos" / "source.jpeg").write_bytes(self.jpeg(72))
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "placeholder-race-snapshot"
        try:
            with mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_MEDIA_BYTES", 0
            ):
                inspection = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)
        outside = self.base / "outside-canary"
        outside.write_text("UNCHANGED\n", encoding="utf-8")
        destination = snapshot / "photos" / "source.jpeg"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(outside)

        with self.assertRaises(CtxError) as raised:
            retrofit_agent._materialize_validation_placeholders(
                snapshot, inspection
            )

        self.assertEqual(raised.exception.code, "retrofit.snapshot-failed")
        self.assertTrue(destination.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "UNCHANGED\n")

    def test_affected_declared_media_is_required_for_reconciliation(self) -> None:
        root = self.base / "required-artifact-project"
        (root / ".ctx").mkdir(parents=True)
        (root / "photos").mkdir()
        media = root / "photos" / "source.jpeg"
        media.write_bytes(self.jpeg(73))
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: required-artifact-project\n"
            "  name: Required Artifact Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Required Artifact Project\n"
            "artifacts:\n"
            "  - path: photos/source.jpeg\n"
            "    role: Canonical visual source.\n",
            encoding="utf-8",
        )
        seal_freshness(root)
        media.write_bytes(self.jpeg(74))
        status = project_status(root)
        required = reconciliation._required_inspection_paths(status)
        self.assertIn("photos/source.jpeg", required)

        def fake_reconcile_agent(
            inventory: object,
            _status: object,
            work_directory: Path,
            snapshot_root: Path,
            inspection: object,
        ) -> Path:
            self.assertIn(
                "photos/source.jpeg",
                getattr(inspection, "copied_paths"),
            )
            self.assertEqual(
                (snapshot_root / "photos" / "source.jpeg").read_bytes(),
                media.read_bytes(),
            )
            result = work_directory / "reconcile-agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [],
                        "acknowledgements": [
                            {
                                "uri": "ctx://required-artifact-project",
                                "reason": "Visual bytes changed without durable meaning.",
                            }
                        ],
                        "summary": "Reviewed the complete declared visual artifact.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        with (
            mock.patch.object(retrofit_agent, "MAX_INSPECTION_MEDIA_BYTES", 0),
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=fake_reconcile_agent,
            ),
        ):
            result = reconciliation.reconcile_project(root)

        self.assertIsNotNone(result.lock)
        self.assertTrue(project_status(root).fresh)

    def test_catalog_only_media_remains_a_freshness_dependency(self) -> None:
        root = self.base / "media-freshness-project"
        (root / ".ctx").mkdir(parents=True)
        (root / "photos").mkdir()
        media = root / "photos" / "source.jpeg"
        media.write_bytes(self.jpeg(81))
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: media-freshness-project\n"
            "  name: Media Freshness Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Media Freshness Project\n",
            encoding="utf-8",
        )
        inventory = inventory_repository(root)
        root_fd = _open_directory_no_follow(inventory.root)
        self.assertIsNotNone(root_fd)
        assert root_fd is not None
        snapshot = self.base / "media-freshness-snapshot"
        try:
            with mock.patch.object(
                retrofit_agent, "MAX_INSPECTION_MEDIA_BYTES", 0
            ):
                inspection = retrofit_agent._build_filtered_snapshot(
                    inventory, root_fd, snapshot
                )
        finally:
            os.close(root_fd)
        self.assertNotIn("photos/source.jpeg", inspection.copied_paths)

        seal_freshness(root)
        media.write_bytes(self.jpeg(82))

        status = project_status(root)
        self.assertFalse(status.fresh)
        self.assertEqual(status.nodes[0].state, "stale")

    def test_manifest_cannot_cite_generated_catalog(self) -> None:
        root = self.base / "adapter-artifact-project"
        root.mkdir()
        work = self.base / "adapter-artifact-work"
        work.mkdir()
        content = (
            "version: 1\n"
            "project:\n"
            "  id: adapter-artifact-project\n"
            "  name: Adapter Artifact Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Adapter Artifact Project\n"
            "artifacts:\n"
            f"  - path: {retrofit_agent.INSPECTION_CATALOG_PATH}\n"
            "    role: Invalid generated adapter data.\n"
        )

        with self.assertRaises(CtxError) as raised:
            retrofit_agent._prepare_proposals(
                root,
                [{"path": ".ctx/context.yaml", "content": content}],
                work,
            )

        self.assertEqual(raised.exception.code, "retrofit.agent-output-invalid")
        self.assertIn("generated inspection adapter data", raised.exception.message)

    def test_reconciliation_tracking_change_is_not_a_false_source_race(self) -> None:
        root = self.base / "tracking-reconcile-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (root / "generated.txt").write_text("DERIVED\n", encoding="utf-8")
        original_manifest = (
            "version: 1\n"
            "project:\n"
            "  id: tracking-reconcile-project\n"
            "  name: Tracking Reconcile Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Tracking Reconcile Project\n"
        )
        updated_manifest = original_manifest + (
            "tracking:\n"
            "  exclude:\n"
            "    - generated.txt\n"
        )
        (root / ".ctx" / "context.yaml").write_text(
            original_manifest,
            encoding="utf-8",
        )
        seal_freshness(root)
        source.write_text("VALUE = 2\n", encoding="utf-8")

        def fake_reconcile_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "reconcile-agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {
                                "path": ".ctx/context.yaml",
                                "content": updated_manifest,
                            }
                        ],
                        "acknowledgements": [],
                        "summary": "Updated deterministic tracking scope.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        with mock.patch.object(
            reconciliation,
            "_run_codex",
            side_effect=fake_reconcile_agent,
        ):
            result = reconciliation.reconcile_project(root)

        self.assertIsNotNone(result.lock)
        self.assertIn(
            "generated.txt",
            (root / ".ctx" / "context.yaml").read_text(encoding="utf-8"),
        )
        self.assertTrue(project_status(root).fresh)

    def test_reconciliation_rejects_concurrent_edit_to_acknowledged_manifest(
        self,
    ) -> None:
        root = self.base / "acknowledged-manifest-race-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        manifest = root / ".ctx" / "context.yaml"
        original_manifest = (
            "version: 1\n"
            "project:\n"
            "  id: acknowledged-manifest-race-project\n"
            "  name: Acknowledged Manifest Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Acknowledged Manifest Race Project\n"
            "  summary: Original reviewed meaning.\n"
        )
        concurrent_manifest = original_manifest.replace(
            "Original reviewed meaning", "Concurrent unreviewed meaning"
        )
        manifest.write_text(original_manifest, encoding="utf-8")
        seal_freshness(root)
        previous_lock = (root / ".ctx" / "lock.json").read_bytes()
        source.write_text("VALUE = 2\n", encoding="utf-8")

        def fake_reconcile_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "reconcile-agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [],
                        "acknowledgements": [
                            {
                                "uri": "ctx://acknowledged-manifest-race-project",
                                "reason": "Implementation-only source change.",
                            }
                        ],
                        "summary": "Acknowledged the reviewed source change.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        real_seal = seal_freshness

        def mutate_during_seal(path: Path) -> object:
            manifest.write_text(concurrent_manifest, encoding="utf-8")
            return real_seal(path)

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=fake_reconcile_agent,
            ),
            mock.patch.object(
                reconciliation,
                "seal_freshness",
                side_effect=mutate_during_seal,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "reconcile.project-changed")
        self.assertEqual(manifest.read_text(encoding="utf-8"), concurrent_manifest)
        self.assertEqual((root / ".ctx" / "lock.json").read_bytes(), previous_lock)
        self.assertFalse(project_status(root).fresh)

    def test_reconciliation_protects_pre_agent_manifest_before_publish(self) -> None:
        root = self.base / "proposal-manifest-race-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        manifest = root / ".ctx" / "context.yaml"
        original_manifest = (
            "version: 1\n"
            "project:\n"
            "  id: proposal-manifest-race-project\n"
            "  name: Proposal Manifest Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Proposal Manifest Race Project\n"
            "  summary: Original meaning.\n"
        )
        proposed_manifest = original_manifest.replace(
            "Original meaning", "Reviewed durable meaning"
        )
        concurrent_manifest = original_manifest.replace(
            "Original meaning", "Concurrent unreviewed meaning"
        )
        manifest.write_text(original_manifest, encoding="utf-8")
        seal_freshness(root)
        previous_lock = (root / ".ctx" / "lock.json").read_bytes()
        source.write_text("VALUE = 2\n", encoding="utf-8")

        def fake_reconcile_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
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
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        real_publish = reconciliation._publish

        def mutate_before_publish(
            root_fd: int,
            project_root: Path,
            proposals: object,
            expected_manifests: object,
        ) -> object:
            manifest.write_text(concurrent_manifest, encoding="utf-8")
            return real_publish(
                root_fd,
                project_root,
                proposals,
                expected_manifests,
            )

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=fake_reconcile_agent,
            ),
            mock.patch.object(
                reconciliation,
                "_publish",
                side_effect=mutate_before_publish,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "reconcile.manifest-changed")
        self.assertEqual(manifest.read_text(encoding="utf-8"), concurrent_manifest)
        self.assertEqual((root / ".ctx" / "lock.json").read_bytes(), previous_lock)

    def test_explicit_acknowledgement_rejects_change_during_seal(self) -> None:
        root = self.base / "explicit-acknowledgement-race-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: explicit-acknowledgement-race-project\n"
            "  name: Explicit Acknowledgement Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Explicit Acknowledgement Race Project\n",
            encoding="utf-8",
        )
        seal_freshness(root)
        previous_lock = (root / ".ctx" / "lock.json").read_bytes()
        source.write_text("VALUE = 2\n", encoding="utf-8")
        real_seal = seal_freshness

        def mutate_during_seal(path: Path) -> object:
            source.write_text("VALUE = 3\n", encoding="utf-8")
            return real_seal(path)

        with mock.patch.object(
            reconciliation,
            "seal_freshness",
            side_effect=mutate_during_seal,
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(
                    root,
                    acknowledge_reason="Reviewed as implementation-only.",
                )

        self.assertEqual(raised.exception.code, "reconcile.project-changed")
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 3\n")
        self.assertEqual((root / ".ctx" / "lock.json").read_bytes(), previous_lock)
        self.assertFalse(project_status(root).fresh)

    def test_obsolete_entry_cleanup_rejects_change_during_seal(self) -> None:
        root = self.base / "obsolete-entry-race-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: obsolete-entry-race-project\n"
            "  name: Obsolete Entry Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Obsolete Entry Race Project\n",
            encoding="utf-8",
        )
        seal_freshness(root)
        lock = root / ".ctx" / "lock.json"
        payload = json.loads(lock.read_text(encoding="utf-8"))
        payload["nodes"]["ctx://obsolete-entry-race-project/removed"] = {
            "source_fingerprint": f"sha256:{'0' * 64}",
            "context_fingerprint": f"sha256:{'1' * 64}",
        }
        lock.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        previous_lock = lock.read_bytes()
        self.assertFalse(project_status(root).fresh)
        self.assertEqual(
            [node.state for node in project_status(root).nodes],
            ["fresh"],
        )
        real_seal = seal_freshness

        def mutate_during_seal(path: Path) -> object:
            source.write_text("VALUE = 2\n", encoding="utf-8")
            return real_seal(path)

        with mock.patch.object(
            reconciliation,
            "seal_freshness",
            side_effect=mutate_during_seal,
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "reconcile.project-changed")
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
        self.assertEqual(lock.read_bytes(), previous_lock)

    def test_reconciliation_rejects_root_replacement_during_live_validation(
        self,
    ) -> None:
        root = self.base / "live-validation-root-race-project"
        displaced = self.base / "live-validation-original-root"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        original_manifest = (
            "version: 1\n"
            "project:\n"
            "  id: live-validation-root-race-project\n"
            "  name: Live Validation Root Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Live Validation Root Race Project\n"
            "  summary: Original meaning.\n"
        )
        proposed_manifest = original_manifest.replace(
            "Original meaning", "Reviewed durable meaning"
        )
        (root / ".ctx" / "context.yaml").write_text(
            original_manifest,
            encoding="utf-8",
        )
        seal_freshness(root)
        source.write_text("VALUE = 2\n", encoding="utf-8")

        def fake_reconcile_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
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
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        real_validate = reconciliation.validate_project
        canonical_root = root.resolve()
        swapped = False

        def swap_during_live_validation(path: Path, *, strict: bool) -> object:
            nonlocal swapped
            if Path(path).resolve() == canonical_root and not swapped:
                swapped = True
                root.rename(displaced)
                (root / ".ctx").mkdir(parents=True)
                (root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
                (root / ".ctx" / "context.yaml").write_text(
                    original_manifest,
                    encoding="utf-8",
                )
            return real_validate(path, strict=strict)

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=fake_reconcile_agent,
            ),
            mock.patch.object(
                reconciliation,
                "validate_project",
                side_effect=swap_during_live_validation,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "reconcile.project-changed")
        self.assertEqual(
            (displaced / ".ctx" / "context.yaml").read_text(encoding="utf-8"),
            original_manifest,
        )

    def test_reconciliation_rejects_root_replacement_during_seal(self) -> None:
        root = self.base / "freshness-seal-root-race-project"
        displaced = self.base / "freshness-seal-original-root"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        original_manifest = (
            "version: 1\n"
            "project:\n"
            "  id: freshness-seal-root-race-project\n"
            "  name: Freshness Seal Root Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Freshness Seal Root Race Project\n"
            "  summary: Original meaning.\n"
        )
        proposed_manifest = original_manifest.replace(
            "Original meaning", "Reviewed durable meaning"
        )
        (root / ".ctx" / "context.yaml").write_text(
            original_manifest,
            encoding="utf-8",
        )
        seal_freshness(root)
        source.write_text("VALUE = 2\n", encoding="utf-8")

        def fake_reconcile_agent(
            _inventory: object,
            _status: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
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
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        real_seal = seal_freshness

        def swap_during_seal(_path: Path) -> object:
            root.rename(displaced)
            (root / ".ctx").mkdir(parents=True)
            (root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            (root / ".ctx" / "context.yaml").write_text(
                original_manifest,
                encoding="utf-8",
            )
            return real_seal(root)

        with (
            mock.patch.object(
                reconciliation,
                "_run_codex",
                side_effect=fake_reconcile_agent,
            ),
            mock.patch.object(
                reconciliation,
                "seal_freshness",
                side_effect=swap_during_seal,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                reconciliation.reconcile_project(root)

        self.assertEqual(raised.exception.code, "reconcile.project-changed")
        self.assertEqual(
            (displaced / ".ctx" / "context.yaml").read_text(encoding="utf-8"),
            original_manifest,
        )

    def test_late_source_change_is_rejected_before_manifest_publication(self) -> None:
        root = self.base / "late-race-project"
        root.mkdir()
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        manifest = (
            "version: 1\n"
            "project:\n"
            "  id: late-race-project\n"
            "  name: Late Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Late Race Project\n"
        )

        def fake_agent(
            inventory: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {"path": ".ctx/context.yaml", "content": manifest}
                        ],
                        "summary": "root proposal",
                        **self.root_review_envelope(inventory),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        original_prepare = retrofit_agent._prepare_proposals

        def prepare_then_mutate(*args: object, **kwargs: object) -> object:
            proposals = original_prepare(*args, **kwargs)
            source.write_text("VALUE = 2\n", encoding="utf-8")
            return proposals

        with (
            mock.patch.object(retrofit_agent, "_run_codex", side_effect=fake_agent),
            mock.patch.object(
                retrofit_agent,
                "_prepare_proposals",
                side_effect=prepare_then_mutate,
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent.run_agent_retrofit(root)

        self.assertEqual(raised.exception.code, "retrofit.source-changed")
        self.assertFalse((root / ".ctx").exists())

    def test_source_change_during_lifecycle_rolls_back_lock_and_manifests(
        self,
    ) -> None:
        root = self.base / "finalization-race-project"
        root.mkdir()
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        manifest = (
            "version: 1\n"
            "project:\n"
            "  id: finalization-race-project\n"
            "  name: Finalization Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Finalization Race Project\n"
        )

        def fake_agent(
            inventory: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {"path": ".ctx/context.yaml", "content": manifest}
                        ],
                        "summary": "root proposal",
                        **self.root_review_envelope(inventory),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        initialize = lifecycle.initialize_freshness

        def mutate_during_initialize(path: Path) -> object:
            source.write_text("VALUE = 2\n", encoding="utf-8")
            return initialize(path)

        finalize = partial(
            lifecycle.complete_retrofit,
            enable_codex_hooks=False,
        )
        with (
            mock.patch.object(retrofit_agent, "_run_codex", side_effect=fake_agent),
            mock.patch.object(
                lifecycle,
                "initialize_freshness",
                side_effect=mutate_during_initialize,
            ),
            mock.patch.dict(
                os.environ,
                {"CTX_HOME": str(self.base / "finalization-ctx-home")},
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent.run_agent_retrofit(root, finalize=finalize)

        self.assertEqual(raised.exception.code, "retrofit.source-changed")
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
        self.assertFalse((root / ".ctx").exists())

    def test_created_manifest_tamper_during_finalization_is_rejected(self) -> None:
        root = self.base / "created-manifest-finalization-race"
        root.mkdir()
        (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        manifest = (
            "version: 1\n"
            "project:\n"
            "  id: created-manifest-finalization-race\n"
            "  name: Created Manifest Finalization Race\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Created Manifest Finalization Race\n"
        )

        def fake_agent(
            inventory: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {"path": ".ctx/context.yaml", "content": manifest}
                        ],
                        "summary": "root proposal",
                        **self.root_review_envelope(inventory),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        def tamper_during_finalize(
            path: Path,
            *,
            verify_unchanged: object,
        ) -> None:
            target = path / ".ctx" / "context.yaml"
            original = target.read_bytes()
            metadata = target.stat()
            target.write_bytes(original.replace(b"Created", b"Altered", 1))
            try:
                assert callable(verify_unchanged)
                verify_unchanged()
            finally:
                target.write_bytes(original)
                os.chmod(target, stat.S_IMODE(metadata.st_mode))
                os.utime(
                    target,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )

        with mock.patch.object(
            retrofit_agent,
            "_run_codex",
            side_effect=fake_agent,
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent.run_agent_retrofit(
                    root,
                    finalize=tamper_during_finalize,
                )

        self.assertEqual(raised.exception.code, "retrofit.destination-changed")
        self.assertFalse((root / ".ctx").exists())

    def test_reviewed_lock_cas_preserves_concurrent_update(self) -> None:
        root = self.base / "reviewed-lock-cas-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: reviewed-lock-cas-project\n"
            "  name: Reviewed Lock CAS Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Reviewed Lock CAS Project\n",
            encoding="utf-8",
        )
        lock = seal_freshness(root).path
        baseline = lock.read_bytes()
        source.write_text("VALUE = 2\n", encoding="utf-8")
        concurrent = b'{"concurrent":true}\n'
        read_lock = freshness._read_lock_at
        reads = 0

        def read_then_change(
            directory_fd: int,
            name: str,
            path: Path,
        ) -> object:
            nonlocal reads
            result = read_lock(directory_fd, name, path)
            reads += 1
            if reads == 1:
                lock.write_bytes(concurrent)
            return result

        with mock.patch.object(
            freshness,
            "_read_lock_at",
            side_effect=read_then_change,
        ):
            with self.assertRaises(CtxError) as raised:
                freshness.seal_freshness(
                    root,
                    expected_previous=baseline,
                    mismatch_code="lock.review-baseline-changed",
                    mismatch_message="freshness lock changed after review",
                )

        self.assertEqual(raised.exception.code, "lock.review-baseline-changed")
        self.assertEqual(lock.read_bytes(), concurrent)

    def test_rollback_uses_written_bytes_and_preserves_later_lock(self) -> None:
        root = self.base / "exact-lock-rollback-project"
        (root / ".ctx").mkdir(parents=True)
        (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: exact-lock-rollback-project\n"
            "  name: Exact Lock Rollback Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Exact Lock Rollback Project\n",
            encoding="utf-8",
        )
        lock = seal_freshness(root).path
        baseline = lock.read_bytes()
        feature = root / "feature" / ".ctx"
        feature.mkdir(parents=True)
        (feature / "context.yaml").write_text(
            "version: 1\n"
            "node:\n"
            "  id: feature\n"
            "  name: Feature\n",
            encoding="utf-8",
        )
        concurrent = b'{"concurrent":true}\n'
        seal = lifecycle.seal_freshness

        def seal_then_change(path: Path, **kwargs: object) -> object:
            result = seal(path, **kwargs)
            result.path.write_bytes(concurrent)
            return result

        with (
            mock.patch.object(
                lifecycle,
                "seal_freshness",
                side_effect=seal_then_change,
            ),
            mock.patch.object(
                lifecycle,
                "register_project",
                side_effect=CtxError("registry.injected", "injected failure"),
            ),
        ):
            with self.assertRaises(CtxError) as raised:
                lifecycle.complete_retrofit(
                    root,
                    enable_codex_hooks=False,
                    replace_fresh_lock=baseline,
                )

        self.assertEqual(raised.exception.code, "lock.rollback-failed")
        self.assertEqual(lock.read_bytes(), concurrent)

    def test_fresh_baseline_propagates_operational_status_errors(self) -> None:
        root = self.base / "baseline-status-error"
        root.mkdir()
        injected = CtxError("status.operational", "injected status failure", exit_code=4)
        with mock.patch.object(
            retrofit_agent,
            "project_status",
            side_effect=injected,
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent._fresh_lock_baseline(root)

        self.assertIs(raised.exception, injected)

    def test_source_change_during_registration_rolls_back_all_lifecycle_writes(
        self,
    ) -> None:
        root = self.base / "registration-race-project"
        root.mkdir()
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        manifest = (
            "version: 1\n"
            "project:\n"
            "  id: registration-race-project\n"
            "  name: Registration Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Registration Race Project\n"
        )

        def fake_agent(
            inventory: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {"path": ".ctx/context.yaml", "content": manifest}
                        ],
                        "summary": "root proposal",
                        **self.root_review_envelope(inventory),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        register = lifecycle.register_project

        def register_then_mutate(path: Path) -> object:
            registration = register(path)
            source.write_text("VALUE = 2\n", encoding="utf-8")
            return registration

        ctx_home = self.base / "registration-race-ctx-home"
        with (
            mock.patch.object(retrofit_agent, "_run_codex", side_effect=fake_agent),
            mock.patch.object(
                lifecycle,
                "register_project",
                side_effect=register_then_mutate,
            ),
            mock.patch.dict(os.environ, {"CTX_HOME": str(ctx_home)}),
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent.run_agent_retrofit(
                    root,
                    finalize=lifecycle.complete_retrofit,
                )

        self.assertEqual(raised.exception.code, "retrofit.source-changed")
        self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
        self.assertFalse((root / ".ctx" / "context.yaml").exists())
        self.assertFalse((root / ".ctx" / "lock.json").exists())
        self.assertFalse((root / ".codex" / "hooks.json").exists())
        self.assertFalse((ctx_home / "registry.json").exists())

    def test_failed_guard_preserves_an_unchanged_existing_registration(self) -> None:
        root = self.base / "existing-registration-project"
        (root / ".ctx").mkdir(parents=True)
        source = root / "app.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (root / ".ctx" / "context.yaml").write_text(
            "version: 1\n"
            "project:\n"
            "  id: existing-registration-project\n"
            "  name: Existing Registration Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Existing Registration Project\n",
            encoding="utf-8",
        )
        seal_freshness(root)
        ctx_home = self.base / "existing-registration-ctx-home"
        with mock.patch.dict(os.environ, {"CTX_HOME": str(ctx_home)}):
            registered = lifecycle.register_project(root)
            self.assertEqual(registered.action, "registered")
            registry_path = ctx_home / "registry.json"
            before_registry = registry_path.read_bytes()
            register = lifecycle.register_project

            def register_then_mutate(path: Path) -> object:
                result = register(path)
                self.assertEqual(result.action, "unchanged")
                source.write_text("VALUE = 2\n", encoding="utf-8")
                return result

            def verify_unchanged() -> None:
                if source.read_text(encoding="utf-8") != "VALUE = 1\n":
                    raise CtxError(
                        "retrofit.source-changed",
                        "injected registration race",
                        exit_code=4,
                    )

            with mock.patch.object(
                lifecycle,
                "register_project",
                side_effect=register_then_mutate,
            ):
                with self.assertRaises(CtxError) as raised:
                    lifecycle.complete_retrofit(
                        root,
                        enable_codex_hooks=False,
                        verify_unchanged=verify_unchanged,
                    )

            self.assertEqual(raised.exception.code, "retrofit.source-changed")
            self.assertEqual(registry_path.read_bytes(), before_registry)

    def test_root_replacement_during_finalization_rolls_back_manifests(
        self,
    ) -> None:
        root = self.base / "root-identity-race-project"
        root.mkdir()
        (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        manifest = (
            "version: 1\n"
            "project:\n"
            "  id: root-identity-race-project\n"
            "  name: Root Identity Race Project\n"
            "  aliases: []\n"
            "node:\n"
            "  id: root\n"
            "  name: Root Identity Race Project\n"
        )

        def fake_agent(
            inventory: object,
            work_directory: Path,
            _snapshot_root: Path,
            _inspection: object,
        ) -> Path:
            result = work_directory / "agent-result.json"
            result.write_text(
                json.dumps(
                    {
                        "manifests": [
                            {"path": ".ctx/context.yaml", "content": manifest}
                        ],
                        "summary": "root proposal",
                        **self.root_review_envelope(inventory),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return result

        def replace_root_during_finalize(
            path: Path,
            *,
            verify_unchanged: object,
        ) -> None:
            displaced = path.with_name(f"{path.name}-displaced")
            path.rename(displaced)
            path.mkdir()
            try:
                assert callable(verify_unchanged)
                verify_unchanged()
            finally:
                path.rmdir()
                displaced.rename(path)

        with mock.patch.object(
            retrofit_agent,
            "_run_codex",
            side_effect=fake_agent,
        ):
            with self.assertRaises(CtxError) as raised:
                retrofit_agent.run_agent_retrofit(
                    root,
                    finalize=replace_root_during_finalize,
                )

        self.assertEqual(raised.exception.code, "retrofit.root-changed")
        self.assertEqual((root / "app.py").read_text(encoding="utf-8"), "VALUE = 1\n")
        self.assertFalse((root / ".ctx").exists())


if __name__ == "__main__":
    unittest.main()
