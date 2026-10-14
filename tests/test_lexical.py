"""Checks label-cue removal and train-only lexical fitting."""

import unittest

from vulnscope.lexical import Vocabulary, tokenize_cpp


class LexicalTests(unittest.TestCase):
    def test_removes_comments_and_generated_names_but_keeps_security_operations(self):
        code = '''static void CWE121_example_01_bad() {
            /* POTENTIAL FLAW: bad */
            int x = 10;
            if (x >= 0) free(data);
            puts("good"); // FIX: false cue
            dataBadBuffer = dataGoodBuffer;
        }'''
        tokens = tokenize_cpp(code)
        self.assertNotIn("POTENTIAL", tokens)
        self.assertNotIn("FIX", tokens)
        self.assertNotIn("CWE121_example_01_bad", tokens)
        self.assertNotIn("static", tokens)
        self.assertNotIn("void", tokens)
        self.assertNotIn("dataBadBuffer", tokens)
        self.assertNotIn("dataGoodBuffer", tokens)
        self.assertIn("<identifier>", tokens)
        self.assertIn(">=", tokens)
        self.assertIn("free", tokens)
        self.assertIn("10", tokens)
        self.assertIn("<string>", tokens)

    def test_vocabulary_does_not_learn_validation_only_token(self):
        vocabulary = Vocabulary.fit([("malloc", "(", "1", ")"), ("malloc", "(", "2", ")")], min_df=2)
        self.assertEqual(vocabulary.tokens, ("(", ")", "malloc"))
        self.assertNotIn("dangerous_new_api", vocabulary.tokens)
        self.assertEqual(vocabulary.transform([("dangerous_new_api", "malloc")])[0], [0.0, 0.0, 1.0])


if __name__ == "__main__":
    unittest.main()
