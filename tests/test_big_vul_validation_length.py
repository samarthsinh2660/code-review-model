"""Length strata use training boundaries, never validation-derived bins."""

import unittest

import numpy as np

from scripts.compare_big_vul_validation_length import _length_bins


class BigVulValidationLengthTests(unittest.TestCase):
    def test_train_only_edges_and_valid_pair_count(self):
        train = np.arange(1, 11, dtype=float)
        validation = np.array([1, 2, 5, 6, 9, 10], dtype=float)
        labels = np.array([1, 0, 1, 0, 1, 0], dtype=np.int8)
        scores = np.array([0.9, 0.1, 0.8, 0.2, 0.7, 0.3])
        result = _length_bins(train, validation, labels, {"model": scores})
        np.testing.assert_allclose(result["train_only_token_count_edges"], [2.8, 4.6, 6.4, 8.2])
        self.assertEqual(sum(item["samples"] for item in result["bins"]), 6)
        self.assertGreater(result["comparable_positive_negative_pairs"], 0)
        self.assertEqual(result["within_bin_pair_weighted_roc_auc"]["model"], 1.0)


if __name__ == "__main__":
    unittest.main()
