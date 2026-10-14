"""The size-only diagnostic preserves natural labels and handles invalid cohorts."""

import unittest

from scripts.audit_big_vul_length import _summarize


class BigVulLengthAuditTests(unittest.TestCase):
    def test_length_ranking_and_medians(self):
        result = _summarize([(0, 2), (1, 8), (0, 3), (1, 10)])
        self.assertEqual(result["samples"], 4)
        self.assertEqual(result["positives"], 2)
        self.assertEqual(result["median_tokens_by_label"], {"0": 2.5, "1": 9.0})
        self.assertEqual(result["length_only_ranking"]["average_precision"], 1.0)

    def test_single_class_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "both labels"):
            _summarize([(0, 2), (0, 3)])


if __name__ == "__main__":
    unittest.main()
