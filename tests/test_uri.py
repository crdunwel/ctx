from __future__ import annotations

import unittest

from ctx.diagnostics import CtxError
from ctx.uri import ContextUri, node_uri, parse_ctx_uri


class ContextUriTests(unittest.TestCase):
    def test_canonical_round_trip(self) -> None:
        examples = {
            "ctx://permit-atlas": ContextUri("permit-atlas"),
            "ctx://permit-atlas/forms": ContextUri("permit-atlas", ("forms",)),
            "ctx://permit-atlas/domain/forms#progressive-form": ContextUri(
                "permit-atlas", ("domain", "forms"), "progressive-form"
            ),
        }
        for text, expected in examples.items():
            with self.subTest(text=text):
                parsed = parse_ctx_uri(text)
                self.assertEqual(parsed, expected)
                self.assertEqual(str(parsed), text)

    def test_root_node_is_omitted_from_uri(self) -> None:
        self.assertEqual(node_uri("permit-atlas", ()), "ctx://permit-atlas")

    def test_builders_reject_invalid_identity(self) -> None:
        for arguments in (
            ("Bad ID", (), None),
            ("project", ("../forms",), None),
            ("project", (), "bad/item"),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(CtxError):
                ContextUri(*arguments)

    def test_rejects_noncanonical_or_unsafe_references(self) -> None:
        invalid = (
            "http://permit-atlas",
            "ctx://",
            "ctx://Permit-Atlas",
            "ctx://permit-atlas/",
            "ctx://permit-atlas//forms",
            "ctx://permit-atlas/../forms",
            "ctx://permit-atlas/forms?x=1",
            "ctx://permit-atlas/forms#",
            "ctx://permit-atlas/forms#bad/id",
            "ctx://permit-atlas/forms%2Fsecret",
            "ctx://user@permit-atlas/forms",
            " ctx://permit-atlas/forms",
            "ctx://permit-atlas/forms ",
            "ctx://permit-\natlas/forms",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(CtxError):
                parse_ctx_uri(value)


if __name__ == "__main__":
    unittest.main()
