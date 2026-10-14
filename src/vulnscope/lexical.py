"""C/C++ lexical features with Juliet label cues removed."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass


_TOKEN = re.compile(
    r"//[^\n]*|/\*[\s\S]*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"
    r"|[A-Za-z_]\w*|(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)"
    r"|>>=|<<=|->\*|\.\.\.|==|!=|<=|>=|&&|\|\||\+\+|--|->|::|"
    r"\+=|-=|\*=|/=|%=|<<|>>|[^\s]"
)
_GENERATED = re.compile(
    r"^(?:CWE\d+\w*|(?:bad|good)(?:[A-Z_0-9]\w*)?|\w*(?:Bad|Good)[A-Z_0-9]\w*)$"
)


def tokenize_cpp(source: str) -> tuple[str, ...]:
    """Tokenize a C/C++ function body without generated label cues."""

    tokens = []
    for match in _TOKEN.finditer(source):
        value = match.group()
        if value.startswith("//") or value.startswith("/*"):
            continue
        if value.startswith('"'):
            value = "<string>"
        elif value.startswith("'"):
            value = "<char>"
        elif _GENERATED.fullmatch(value):
            value = "<identifier>"
        tokens.append(value)
    try:
        body_start = tokens.index("{")
    except ValueError as error:
        raise ValueError("function source has no body brace") from error
    return tuple(tokens[body_start:])


@dataclass(frozen=True)
class Vocabulary:
    """A fixed token-to-column mapping fitted on training data only."""

    tokens: tuple[str, ...]

    @classmethod
    def fit(cls, documents: list[tuple[str, ...]], max_features: int = 4096, min_df: int = 2) -> "Vocabulary":
        if max_features < 1 or min_df < 1:
            raise ValueError("max_features and min_df must be positive")
        document_frequency: Counter[str] = Counter()
        for document in documents:
            document_frequency.update(set(document))
        selected = sorted(
            (token for token, count in document_frequency.items() if count >= min_df),
            key=lambda token: (-document_frequency[token], token),
        )[:max_features]
        return cls(tuple(selected))

    def transform(self, documents: list[tuple[str, ...]]) -> list[list[float]]:
        columns = {token: index for index, token in enumerate(self.tokens)}
        output = []
        for document in documents:
            vector = [0.0] * len(self.tokens)
            for token, count in Counter(document).items():
                index = columns.get(token)
                if index is not None:
                    vector[index] = float(count)
            output.append(vector)
        return output
