"""Hand-calculated ranking and threshold metrics."""

import unittest

import numpy as np

from vulnscope.metrics import choose_f1_threshold, ranking_metrics, threshold_metrics


class MetricsTests(unittest.TestCase):
    def test_nonperfect_ranking_and_confusion_counts(self):
        y = np.asarray([1, 0, 1, 0])
        scores = np.asarray([0.9, 0.8, 0.2, 0.1])
        ranked = ranking_metrics(y, scores)
        self.assertAlmostEqual(ranked["average_precision"], 5 / 6)
        self.assertAlmostEqual(ranked["roc_auc"], 0.75)
        at_half = threshold_metrics(y, scores, 0.5)
        self.assertEqual([at_half[key] for key in ("tp", "fp", "tn", "fn")], [1, 1, 1, 1])
        self.assertEqual(at_half["precision"], 0.5)
        self.assertEqual(at_half["recall"], 0.5)

    def test_ties_are_order_independent(self):
        labels = np.asarray([1, 0, 1, 0])
        scores = np.asarray([0.5, 0.5, 0.5, 0.5])
        expected = ranking_metrics(labels, scores)
        self.assertEqual(expected, ranking_metrics(labels[::-1], scores[::-1]))
        self.assertEqual(expected["roc_auc"], 0.5)
        self.assertEqual(expected["average_precision"], 0.5)

    def test_threshold_selection_uses_f1(self):
        labels = np.asarray([1, 0, 1, 0])
        scores = np.asarray([0.9, 0.8, 0.2, 0.1])
        threshold, metrics = choose_f1_threshold(labels, scores)
        self.assertEqual(threshold, 0.2)
        self.assertAlmostEqual(metrics["f1"], 0.8)


if __name__ == "__main__":
    unittest.main()
