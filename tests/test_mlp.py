"""Finite-difference and save/load checks for our MLP."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from vulnscope.mlp import MLP, fit_mlp


class MLPTests(unittest.TestCase):
    def test_gradients_match_finite_difference(self):
        model = MLP.initialize(2, 3, seed=7)
        x = np.asarray([[1.0, -2.0], [2.0, 1.0], [-1.0, 0.5]])
        y = np.asarray([1.0, 0.0, 1.0])
        _, gradients = model.loss_and_gradients(x, y, l2=0.03)
        epsilon = 1e-6
        for parameter, gradient in zip((model.w1, model.b1, model.w2), gradients[:3]):
            for index in np.ndindex(parameter.shape):
                original = parameter[index]
                parameter[index] = original + epsilon
                plus = model.loss_and_gradients(x, y, l2=0.03)[0]
                parameter[index] = original - epsilon
                minus = model.loss_and_gradients(x, y, l2=0.03)[0]
                parameter[index] = original
                self.assertAlmostEqual(gradient[index], (plus - minus) / (2 * epsilon), places=5)
        original = model.b2
        model.b2 = original + epsilon
        plus = model.loss_and_gradients(x, y, l2=0.03)[0]
        model.b2 = original - epsilon
        minus = model.loss_and_gradients(x, y, l2=0.03)[0]
        model.b2 = original
        self.assertAlmostEqual(gradients[3], (plus - minus) / (2 * epsilon), places=5)

    def test_training_and_reload(self):
        x = np.asarray([[0.0], [0.2], [0.8], [1.0]])
        y = np.asarray([0.0, 0.0, 1.0, 1.0])
        model, history = fit_mlp(x, y, x, y, hidden_size=4, max_epochs=100, patience=10)
        self.assertLess(history[-1]["train_loss"], history[0]["train_loss"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.npz"
            model.save(path)
            np.testing.assert_array_equal(MLP.load(path).predict_scores(x), model.predict_scores(x))


if __name__ == "__main__":
    unittest.main()
