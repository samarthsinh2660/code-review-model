"""One-hidden-layer NumPy MLP implemented for the VulnScope experiment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from vulnscope.logistic import sigmoid


@dataclass
class MLP:
    w1: np.ndarray
    b1: np.ndarray
    w2: np.ndarray
    b2: float

    @classmethod
    def initialize(cls, input_size: int, hidden_size: int, seed: int = 42) -> "MLP":
        if input_size < 1 or hidden_size < 1:
            raise ValueError("layer widths must be positive")
        rng = np.random.default_rng(seed)
        return cls(
            rng.normal(0.0, np.sqrt(2 / input_size), (input_size, hidden_size)),
            np.zeros(hidden_size),
            rng.normal(0.0, np.sqrt(2 / hidden_size), hidden_size),
            0.0,
        )

    def _forward(self, features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if features.ndim != 2 or features.shape[1] != self.w1.shape[0]:
            raise ValueError("feature count does not match MLP")
        pre_activation = features @ self.w1 + self.b1
        hidden = np.maximum(pre_activation, 0)
        logits = hidden @ self.w2 + self.b2
        return pre_activation, logits

    def predict_scores(self, features: np.ndarray) -> np.ndarray:
        return sigmoid(self._forward(features)[1])

    def loss_and_gradients(
        self, features: np.ndarray, labels: np.ndarray, l2: float = 0.0
    ) -> tuple[float, tuple[np.ndarray, np.ndarray, np.ndarray, float]]:
        if labels.shape != (len(features),) or not len(labels) or l2 < 0:
            raise ValueError("invalid labels or L2")
        pre_activation, logits = self._forward(features)
        hidden = np.maximum(pre_activation, 0)
        loss = float(np.mean(np.logaddexp(0, logits) - labels * logits))
        loss += 0.5 * l2 * (np.sum(self.w1 ** 2) + np.sum(self.w2 ** 2))
        delta2 = (sigmoid(logits) - labels) / len(labels)
        grad_w2 = hidden.T @ delta2 + l2 * self.w2
        grad_b2 = float(delta2.sum())
        delta1 = np.outer(delta2, self.w2) * (pre_activation > 0)
        grad_w1 = features.T @ delta1 + l2 * self.w1
        grad_b1 = delta1.sum(axis=0)
        return loss, (grad_w1, grad_b1, grad_w2, grad_b2)

    def copy(self) -> "MLP":
        return MLP(self.w1.copy(), self.b1.copy(), self.w2.copy(), self.b2)

    def save(self, path: Path) -> None:
        np.savez_compressed(path, w1=self.w1, b1=self.b1, w2=self.w2, b2=np.asarray(self.b2))

    @classmethod
    def load(cls, path: Path) -> "MLP":
        with np.load(path, allow_pickle=False) as saved:
            model = cls(saved["w1"], saved["b1"], saved["w2"], float(saved["b2"]))
        if (
            model.w1.ndim != 2 or model.b1.shape != (model.w1.shape[1],)
            or model.w2.shape != model.b1.shape
            or not all(np.all(np.isfinite(value)) for value in (model.w1, model.b1, model.w2))
            or not np.isfinite(model.b2)
        ):
            raise ValueError("invalid MLP artifact")
        return model


def fit_mlp(
    train_x: np.ndarray,
    train_y: np.ndarray,
    val_x: np.ndarray,
    val_y: np.ndarray,
    *,
    hidden_size: int = 16,
    learning_rate: float = 0.01,
    l2: float = 0.01,
    batch_size: int = 64,
    max_epochs: int = 300,
    patience: int = 30,
    seed: int = 42,
) -> tuple[MLP, list[dict[str, float]]]:
    if learning_rate <= 0 or batch_size < 1 or max_epochs < 1 or patience < 1:
        raise ValueError("training settings must be positive")
    if train_x.shape[1] != val_x.shape[1] or not len(train_y) or not len(val_y):
        raise ValueError("train and validation arrays must be nonempty and compatible")
    rng = np.random.default_rng(seed)
    model = MLP.initialize(train_x.shape[1], hidden_size, seed)
    best = model.copy()
    best_loss = float("inf")
    stale = 0
    history = []
    for epoch in range(1, max_epochs + 1):
        for batch in np.array_split(rng.permutation(len(train_y)), max(1, int(np.ceil(len(train_y) / batch_size)))):
            _, (grad_w1, grad_b1, grad_w2, grad_b2) = model.loss_and_gradients(train_x[batch], train_y[batch], l2)
            model.w1 -= learning_rate * grad_w1
            model.b1 -= learning_rate * grad_b1
            model.w2 -= learning_rate * grad_w2
            model.b2 -= learning_rate * grad_b2
        train_loss = model.loss_and_gradients(train_x, train_y, l2)[0]
        val_loss = model.loss_and_gradients(val_x, val_y, l2)[0]
        history.append({"epoch": float(epoch), "train_loss": train_loss, "val_loss": val_loss})
        if val_loss < best_loss - 1e-8:
            best = model.copy()
            best_loss = val_loss
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                break
    return best, history
