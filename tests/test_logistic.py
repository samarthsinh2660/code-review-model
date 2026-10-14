"""Gradient and persistence checks for the custom logistic model."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from vulnscope.logistic import LogisticModel, fit_logistic, loss_and_gradient, sigmoid


class LogisticTests(unittest.TestCase):
    def test_sigmoid_stays_finite_at_extreme_logits(self):
        result = sigmoid(np.asarray([-1000.0, 0.0, 1000.0]))
        np.testing.assert_allclose(result, [0.0, 0.5, 1.0])

    def test_analytical_gradient_matches_finite_difference(self):
        x = np.asarray([[1.0, 2.0], [2.0, -1.0], [0.0, 0.5]])
        y = np.asarray([1.0, 0.0, 1.0])
        w = np.asarray([0.2, -0.3])
        b = 0.1
        loss, gradient_w, gradient_b = loss_and_gradient(x, y, w, b, l2=0.05)
        epsilon = 1e-6
        for index in range(len(w)):
            plus = w.copy(); plus[index] += epsilon
            minus = w.copy(); minus[index] -= epsilon
            numerical = (loss_and_gradient(x, y, plus, b, 0.05)[0] - loss_and_gradient(x, y, minus, b, 0.05)[0]) / (2 * epsilon)
            self.assertAlmostEqual(gradient_w[index], numerical, places=6)
        numerical_b = (loss_and_gradient(x, y, w, b + epsilon, 0.05)[0] - loss_and_gradient(x, y, w, b - epsilon, 0.05)[0]) / (2 * epsilon)
        self.assertAlmostEqual(gradient_b, numerical_b, places=6)
        self.assertGreater(loss, 0)

    def test_training_and_reload_preserve_scores(self):
        x = np.asarray([[-2.0], [-1.0], [1.0], [2.0]])
        y = np.asarray([0.0, 0.0, 1.0, 1.0])
        model, history = fit_logistic(x, y, x, y, max_epochs=50, patience=10)
        self.assertLess(history[-1]["train_loss"], history[0]["train_loss"])
        self.assertGreater(model.predict_scores(x)[-1], model.predict_scores(x)[0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.npz"
            model.save(path)
            loaded = LogisticModel.load(path)
            np.testing.assert_array_equal(loaded.predict_scores(x), model.predict_scores(x))

    def test_train_only_sample_weights_change_one_step_and_reject_bad_shape(self):
        x = np.zeros((4, 1))
        y = np.asarray([0.0, 0.0, 0.0, 1.0])
        plain, _ = fit_logistic(x, y, x, y, max_epochs=1, patience=1)
        weighted, _ = fit_logistic(x, y, x, y, max_epochs=1, patience=1,
                                   train_sample_weights=np.asarray([1.0, 1.0, 1.0, 3.0]))
        self.assertGreater(weighted.predict_scores(x)[0], plain.predict_scores(x)[0])
        with self.assertRaisesRegex(ValueError, "sample weights"):
            fit_logistic(x, y, x, y, train_sample_weights=np.asarray([1.0]))


if __name__ == "__main__":
    unittest.main()
