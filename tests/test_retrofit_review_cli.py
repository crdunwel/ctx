from __future__ import annotations

import contextlib
import io
import unittest
from unittest import mock

from ctx import cli


class RetrofitReviewCliTests(unittest.TestCase):
    def test_review_compatibility_form_is_a_mandatory_dry_run(self) -> None:
        captured: list[object] = []

        def execute(arguments: object) -> int:
            captured.append(arguments)
            return 0

        with mock.patch.object(cli, "_execute", side_effect=execute):
            result = cli.main(["retrofit", "review", "/tmp/example"])

        self.assertEqual(result, 0)
        self.assertEqual(len(captured), 1)
        arguments = captured[0]
        self.assertEqual(arguments.command, "retrofit")
        self.assertEqual(arguments.path, "/tmp/example")
        self.assertTrue(arguments.review)
        self.assertTrue(arguments.dry_run)

    def test_review_modifier_refuses_unreviewed_direct_application(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli.main(["retrofit", "--review", "/tmp/example"])

        self.assertEqual(result, 1)
        self.assertIn("--review requires --dry-run", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
