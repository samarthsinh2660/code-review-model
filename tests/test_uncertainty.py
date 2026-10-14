"""Paired project bootstrap keeps project rows together."""

import unittest

import numpy as np

from vulnscope.uncertainty import project_bootstrap_ap_difference


class UncertaintyTests(unittest.TestCase):
    def test_identical_scores_have_zero_difference(self):
        labels = np.array([1, 0, 1, 0], dtype=np.int8)
        scores = np.array([0.8, 0.1, 0.7, 0.2])
        projects = ["a", "a", "b", "b"]
        result = project_bootstrap_ap_difference(labels, scores, scores, projects, repeats=30, seed=7)
        self.assertEqual(result["valid_replicates"], 30)
        self.assertEqual(result["ci_95"], [0.0, 0.0])

    def test_rejects_bad_shapes_and_single_project(self):
        labels = np.array([1, 0], dtype=np.int8)
        scores = np.array([0.9, 0.1])
        with self.assertRaises(ValueError):
            project_bootstrap_ap_difference(labels, scores, scores, ["a"], repeats=10)
        with self.assertRaises(ValueError):
            project_bootstrap_ap_difference(labels, scores, scores, ["a", "a"], repeats=10)


if __name__ == "__main__":
    unittest.main()
