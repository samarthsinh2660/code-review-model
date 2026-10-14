"""AST features use only the intended source-local function body."""

import unittest

from vulnscope.ast_features import AST_KINDS, ast_body_counts


class AstFeatureTests(unittest.TestCase):
    def test_counts_body_nodes_without_header_or_other_function(self):
        source = b"void bad() { if (x) free(x); }\n"
        ast = {"kind": "TranslationUnitDecl", "inner": [
            {"kind": "FunctionDecl", "name": "header", "loc": {"offset": 5},
             "range": {"begin": {"offset": 0}},
             "inner": [{"kind": "CompoundStmt", "inner": [{"kind": "CallExpr"}]}]},
            {"kind": "FunctionDecl", "name": "bad", "loc": {"offset": 5},
             "range": {"begin": {"offset": 0}},
             "inner": [{"kind": "CompoundStmt", "inner": [
                 {"kind": "IfStmt", "inner": [{"kind": "CallExpr"}]}
             ]}]},
        ]}
        vector = ast_body_counts(ast, source, "bad", 1)
        self.assertEqual(vector[AST_KINDS.index("IfStmt")], 1)
        self.assertEqual(vector[AST_KINDS.index("CallExpr")], 1)
        with self.assertRaisesRegex(ValueError, "expected one AST body"):
            ast_body_counts(ast, source, "missing", 1)


if __name__ == "__main__":
    unittest.main()
