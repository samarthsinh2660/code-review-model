"""High-similarity token-shingle audit; candidates are confirmed exactly."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict


def shingle_hashes(tokens: tuple[str, ...], width: int = 5) -> frozenset[int]:
    """Hash distinct consecutive token windows with a stable 64-bit digest."""

    if width < 1:
        raise ValueError("shingle width must be positive")
    return frozenset(
        int.from_bytes(hashlib.blake2b("\0".join(tokens[start:start + width]).encode("utf-8"),
                                       digest_size=8).digest(), "big")
        for start in range(max(0, len(tokens) - width + 1))
    )


def find_near_pairs(
    train: list[tuple[str, ...]], query: list[tuple[str, ...]],
    *, threshold: float = 0.8, width: int = 5, sketch_size: int = 16,
    min_shingles: int = 3, max_postings: int = 5000,
) -> dict[str, object]:
    """Find candidate cross-cohort pairs and verify their exact shingle Jaccard.

    The bottom-k sketch and posting cap can miss near clones. Counts describe
    the explored candidate space, not a complete proof of no leakage.
    """

    if not 0 < threshold <= 1 or width < 1 or sketch_size < 2 or min_shingles < 1 or max_postings < 1:
        raise ValueError("invalid near-duplicate audit settings")
    train_sets = [shingle_hashes(tokens, width) for tokens in train]
    query_sets = [shingle_hashes(tokens, width) for tokens in query]
    postings: dict[int, list[int]] = defaultdict(list)
    for index, shingles in enumerate(train_sets):
        if len(shingles) < min_shingles:
            continue
        for signature in sorted(shingles)[:sketch_size]:
            postings[signature].append(index)
    large_signatures = {signature for signature, indices in postings.items() if len(indices) > max_postings}
    pairs = []
    compared_pairs = 0
    query_with_candidates = 0
    query_with_capped_signature = 0
    for query_index, shingles in enumerate(query_sets):
        if len(shingles) < min_shingles:
            continue
        candidates: Counter[int] = Counter()
        capped = False
        for signature in sorted(shingles)[:sketch_size]:
            if signature in large_signatures:
                capped = True
                continue
            candidates.update(postings.get(signature, ()))
        query_with_capped_signature += int(capped)
        eligible = [index for index, shared in candidates.items() if shared >= 2]
        query_with_candidates += int(bool(eligible))
        for train_index in eligible:
            other = train_sets[train_index]
            if min(len(shingles), len(other)) / max(len(shingles), len(other)) < threshold:
                continue
            compared_pairs += 1
            intersection = len(shingles & other)
            jaccard = intersection / (len(shingles) + len(other) - intersection)
            if jaccard >= threshold:
                pairs.append({"train_index": train_index, "query_index": query_index,
                              "jaccard": jaccard})
    pairs.sort(key=lambda item: (item["query_index"], -item["jaccard"], item["train_index"]))
    return {
        "pairs": pairs,
        "train_count": len(train), "query_count": len(query),
        "short_train": sum(len(shingles) < min_shingles for shingles in train_sets),
        "short_query": sum(len(shingles) < min_shingles for shingles in query_sets),
        "capped_signature_count": len(large_signatures),
        "query_with_capped_signature": query_with_capped_signature,
        "query_with_candidates": query_with_candidates,
        "compared_pairs": compared_pairs,
        "settings": {"threshold": threshold, "width": width, "sketch_size": sketch_size,
                     "min_shingles": min_shingles, "max_postings": max_postings,
                     "min_shared_sketch_hashes": 2},
    }
