"""Length-normalized lexical features and train-only IDF."""

import unittest

import numpy as np

from vulnscope.frequency_features import fit_idf, transform_frequency
from vulnscope.lexical import Vocabulary


class FrequencyFeatureTests(unittest.TestCase):
    def test_repeating_a_token_distribution_keeps_frequency_features(self):
        vocabulary = Vocabulary(("a", "b"))
        short = ("a", "b")
        doubled = ("a", "b", "a", "b")
        features = transform_frequency([short, doubled], vocabulary)
        np.testing.assert_allclose(features[0], features[1])

    def test_idf_uses_only_supplied_training_documents(self):
        vocabulary = Vocabulary(("common", "rare"))
        train = [("common", "rare"), ("common",), ("common",)]
        idf = fit_idf(train, vocabulary)
        self.assertGreater(idf[1], idf[0])
        self.assertAlmostEqual(float(np.mean(idf)), 1.0, places=6)
        weighted = transform_frequency([("common", "rare")], vocabulary, idf=idf)
        plain = transform_frequency([("common", "rare")], vocabulary)
        np.testing.assert_allclose(weighted[0], plain[0] * idf)

    def test_rejects_empty_document_and_wrong_idf_shape(self):
        vocabulary = Vocabulary(("a",))
        with self.assertRaises(ValueError):
            transform_frequency([()], vocabulary)
        with self.assertRaises(ValueError):
            transform_frequency([("a",)], vocabulary, idf=np.array([1.0, 2.0]))


if __name__ == "__main__":
    unittest.main()
