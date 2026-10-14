"""Body-length-normalized token counts with optional train-only IDF."""

from __future__ import annotations

from collections import Counter

import numpy as np

from vulnscope.lexical import Vocabulary


def fit_idf(train_documents: list[tuple[str, ...]], vocabulary: Vocabulary) -> np.ndarray:
    """Fit smoothed inverse document frequency only on training documents."""

    if not train_documents or not vocabulary.tokens:
        raise ValueError("training documents and vocabulary must be nonempty")
    columns = {token: index for index, token in enumerate(vocabulary.tokens)}
    frequency = np.zeros(len(columns), dtype=np.int64)
    for document in train_documents:
        for token in set(document):
            index = columns.get(token)
            if index is not None:
                frequency[index] += 1
    if np.any(frequency == 0):
        raise ValueError("vocabulary contains a token absent from training")
    values = np.log((len(train_documents) + 1) / (frequency + 1)) + 1.0
    return (values / values.mean()).astype(np.float32)


def transform_frequency(
    documents: list[tuple[str, ...]], vocabulary: Vocabulary, *, idf: np.ndarray | None = None,
) -> np.ndarray:
    """Return log1p(100 × within-body token frequency), optionally times IDF."""

    if not vocabulary.tokens:
        raise ValueError("vocabulary must be nonempty")
    if idf is not None and (idf.shape != (len(vocabulary.tokens),)
                            or not np.all(np.isfinite(idf)) or np.any(idf <= 0)):
        raise ValueError("IDF must be positive, finite, and match vocabulary")
    columns = {token: index for index, token in enumerate(vocabulary.tokens)}
    output = np.zeros((len(documents), len(columns)), dtype=np.float32)
    for row, document in enumerate(documents):
        if not document:
            raise ValueError("function body tokens must be nonempty")
        scale = 100.0 / len(document)
        for token, count in Counter(document).items():
            index = columns.get(token)
            if index is not None:
                output[row, index] = np.log1p(scale * count)
    if idf is not None:
        output *= idf
    return output
