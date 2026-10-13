"""Checks for source-local function spans and flaw-line matching."""

import unittest

from scripts.audit_juliet_functions import function_bodies, map_flaw_lines


class FunctionAuditTests(unittest.TestCase):
    def test_source_offset_rejects_header_declaration(self):
        source = b"void bad() {\n  int x = 1;\n}\n"
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "header_only",
                    "loc": {"offset": 5},
                    "inner": [{"kind": "CompoundStmt", "range": {"begin": {"offset": 11}, "end": {"offset": 29}}}],
                },
                {
                    "kind": "FunctionDecl",
                    "name": "bad",
                    "loc": {"offset": 5},
                    "range": {"begin": {"offset": 0}},
                    "inner": [{"kind": "CompoundStmt", "range": {"begin": {"offset": 11}, "end": {"offset": 26}}}],
                },
            ],
        }
        self.assertEqual(function_bodies(ast, source), [
            {"name": "bad", "declaration_start_line": 1, "start_line": 1, "end_line": 3}
        ])

    def test_flaw_lines_keep_unmatched_and_ambiguous(self):
        bodies = [
            {"name": "one", "declaration_start_line": 1, "start_line": 2, "end_line": 5},
            {"name": "two", "declaration_start_line": 4, "start_line": 4, "end_line": 8},
        ]
        self.assertEqual(map_flaw_lines(bodies, [1, 3, 4, 7, 9]), {
            "matched": [
                {"line": 1, "function": "one", "location": "signature"},
                {"line": 3, "function": "one", "location": "body"},
                {"line": 7, "function": "two", "location": "body"},
            ],
            "unmatched": [9],
            "ambiguous": [{"line": 4, "functions": ["one", "two"]}],
        })


if __name__ == "__main__":
    unittest.main()
