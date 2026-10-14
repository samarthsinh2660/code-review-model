"""Validation-only alert budget selection."""

import unittest

import numpy as np

from vulnscope.alert_policy import choose_budget_threshold


class AlertPolicyTests(unittest.TestCase):
    def test_selects_recall_under_budget_and_keeps_ties_together(self):
        labels = np.array([1, 0, 1, 0, 0])
        scores = np.array([0.9, 0.8, 0.8, 0.2, 0.1])
        threshold, result = choose_budget_threshold(labels, scores, 0.4)
        self.assertEqual(threshold, 0.9)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["fp"], 0)
        self.assertLessEqual(result["flagged_fraction"], 0.4)

    def test_prefers_fewer_false_positives_for_same_recall(self):
        labels = np.array([1, 0, 0, 0])
        scores = np.array([0.9, 0.8, 0.7, 0.1])
        threshold, result = choose_budget_threshold(labels, scores, 0.75)
        self.assertEqual(threshold, 0.9)
        self.assertEqual(result["fp"], 0)

    def test_rejects_invalid_budget_and_impossible_score_one_tie(self):
        with self.assertRaises(ValueError):
            choose_budget_threshold(np.array([1]), np.array([0.5]), 0)
        with self.assertRaises(ValueError):
            choose_budget_threshold(np.array([1, 0]), np.array([1.0, 1.0]), 0.5)


if __name__ == "__main__":
    unittest.main()
