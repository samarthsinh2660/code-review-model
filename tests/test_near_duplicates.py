"""Deterministic shingle candidate audit with exact Jaccard confirmation."""

import unittest

from vulnscope.near_duplicates import find_near_pairs, shingle_hashes


class NearDuplicateTests(unittest.TestCase):
    def test_one_token_edit_is_found_and_unrelated_code_is_not(self):
        original = tuple(f"token{i}" for i in range(50))
        changed = list(original)
        changed[25] = "replacement"
        unrelated = tuple(f"other{i}" for i in range(50))
        result = find_near_pairs([original], [tuple(changed), unrelated], threshold=0.8)
        self.assertEqual([(pair["train_index"], pair["query_index"]) for pair in result["pairs"]], [(0, 0)])
        self.assertGreaterEqual(result["pairs"][0]["jaccard"], 0.8)
        self.assertEqual(result["compared_pairs"], 1)

    def test_short_functions_are_counted_as_uncovered(self):
        result = find_near_pairs([("return", "0")], [("return", "0")])
        self.assertEqual(result["pairs"], [])
        self.assertEqual(result["short_train"], 1)
        self.assertEqual(result["short_query"], 1)

    def test_shingles_and_results_are_deterministic(self):
        tokens = tuple(f"x{i}" for i in range(30))
        self.assertEqual(shingle_hashes(tokens), shingle_hashes(tokens))
        self.assertEqual(find_near_pairs([tokens], [tokens]), find_near_pairs([tokens], [tokens]))


if __name__ == "__main__":
    unittest.main()
