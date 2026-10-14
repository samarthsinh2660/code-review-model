"""Custom NumPy logistic regression for the first vulnerability baseline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np


def sigmoid(logits: np.ndarray) -> np.ndarray:
    positive = logits >= 0
    result = np.empty_like(logits, dtype=np.float64)
    result[positive] = 1.0 / (1.0 + np.exp(-logits[positive]))
    exp_logits = np.exp(logits[~positive])
    result[~positive] = exp_logits / (1.0 + exp_logits)
    return result


def loss_and_gradient(
    features: np.ndarray,
    labels: np.ndarray,
    weights: np.ndarray,
    bias: float,
    l2: float = 0.0,
    sample_weights: np.ndarray | None = None,
) -> tuple[float, np.ndarray, float]:
    """Stable binary cross-entropy and analytical gradient, with optional L2."""

    if features.ndim != 2 or labels.shape != (features.shape[0],) or weights.shape != (features.shape[1],):
        raise ValueError("incompatible feature, label, or weight shapes")
    if not len(labels) or l2 < 0:
        raise ValueError("nonempty labels and nonnegative L2 are required")
    if sample_weights is None:
        sample_weights = np.ones(len(labels), dtype=np.float64)
    if (sample_weights.shape != labels.shape or not np.all(np.isfinite(sample_weights))
            or np.any(sample_weights <= 0)):
        raise ValueError("sample weights must be positive and match labels")
    normalizer = float(sample_weights.sum())
    logits = features @ weights + bias
    losses = np.logaddexp(0.0, logits) - labels * logits
    loss = float((sample_weights @ losses) / normalizer + 0.5 * l2 * (weights @ weights))
    residual = sample_weights * (sigmoid(logits) - labels) / normalizer
    gradient_w = features.T @ residual + l2 * weights
    gradient_b = float(residual.sum())
    return loss, gradient_w, gradient_b


@dataclass
class LogisticModel:
    weights: np.ndarray
    bias: float

    def predict_scores(self, features: np.ndarray) -> np.ndarray:
        if features.ndim != 2 or features.shape[1] != self.weights.shape[0]:
            raise ValueError("feature count does not match model")
        return sigmoid(features @ self.weights + self.bias)

    def save(self, path: Path) -> None:
        np.savez_compressed(path, weights=self.weights, bias=np.asarray(self.bias))

    @classmethod
    def load(cls, path: Path) -> "LogisticModel":
        with np.load(path, allow_pickle=False) as saved:
            weights = saved["weights"]
            bias = float(saved["bias"])
        if weights.ndim != 1 or not np.all(np.isfinite(weights)) or not np.isfinite(bias):
            raise ValueError("invalid logistic model artifact")
        return cls(weights.astype(np.float64), bias)


def fit_logistic(
    train_x: np.ndarray,
    train_y: np.ndarray,
    val_x: np.ndarray,
    val_y: np.ndarray,
    *,
    learning_rate: float = 0.1,
    l2: float = 0.01,
    batch_size: int = 64,
    max_epochs: int = 300,
    patience: int = 30,
    seed: int = 42,
    train_sample_weights: np.ndarray | None = None,
) -> tuple[LogisticModel, list[dict[str, float]]]:
    """Fit minibatches and restore the checkpoint with lowest validation loss."""

    if learning_rate <= 0 or batch_size < 1 or max_epochs < 1 or patience < 1:
        raise ValueError("training settings must be positive")
    if train_x.shape[1] != val_x.shape[1] or not len(train_y) or not len(val_y):
        raise ValueError("train and validation arrays must be nonempty and compatible")
    if train_sample_weights is not None and (
        train_sample_weights.shape != train_y.shape
        or not np.all(np.isfinite(train_sample_weights))
        or np.any(train_sample_weights <= 0)
    ):
        raise ValueError("train sample weights must be finite, positive, and match train labels")
    rng = np.random.default_rng(seed)
    weights = np.zeros(train_x.shape[1], dtype=np.float64)
    bias = 0.0
    best_weights = weights.copy()
    best_bias = bias
    best_loss = float("inf")
    stale = 0
    history: list[dict[str, float]] = []
    for epoch in range(1, max_epochs + 1):
        for batch in np.array_split(rng.permutation(len(train_y)), max(1, int(np.ceil(len(train_y) / batch_size)))):
            batch_weights = train_sample_weights[batch] if train_sample_weights is not None else None
            _, gradient_w, gradient_b = loss_and_gradient(
                train_x[batch], train_y[batch], weights, bias, l2, batch_weights
            )
            weights -= learning_rate * gradient_w
            bias -= learning_rate * gradient_b
        train_loss = loss_and_gradient(train_x, train_y, weights, bias, l2, train_sample_weights)[0]
        val_loss = loss_and_gradient(val_x, val_y, weights, bias, l2)[0]
        history.append({"epoch": float(epoch), "train_loss": train_loss, "val_loss": val_loss})
        if val_loss < best_loss - 1e-8:
            best_loss = val_loss
            best_weights = weights.copy()
            best_bias = bias
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                break
    return LogisticModel(best_weights, best_bias), history
