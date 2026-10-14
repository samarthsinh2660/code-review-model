"""Group related code before assigning immutable dataset splits."""

from __future__ import annotations

from collections import Counter, defaultdict

from vulnscope.lexical import tokenize_cpp
from vulnscope.records import FunctionRecord


SPLIT_NAMES = ("train", "validation", "test")
SPLIT_SHARES = (0.70, 0.15, 0.15)


def _shingles(tokens: tuple[str, ...], width: int) -> set[tuple[str, ...]]:
    if not tokens:
        return set()
    if len(tokens) < width:
        return {tokens}
    return set(zip(*(tokens[index:] for index in range(width))))


def group_near_duplicates(
    records: list[FunctionRecord], threshold: float = 0.8, shingle_width: int = 5
) -> tuple[list[str], dict[str, int]]:
    """Union source groups linked by near-identical normalized token shingles."""

    if not 0 < threshold <= 1 or shingle_width < 1:
        raise ValueError("invalid near-duplicate settings")
    groups = {record.group_id for record in records}
    if None in groups:
        raise ValueError("all records need a provisional group")
    parents = {group: group for group in groups}

    def find(group: str) -> str:
        while parents[group] != group:
            parents[group] = parents[parents[group]]
            group = parents[group]
        return group

    shingles = [_shingles(tokenize_cpp(record.source_code), shingle_width) for record in records]
    near_pairs = 0
    cross_group_edges: set[tuple[str, str]] = set()
    for left, a in enumerate(shingles):
        if not a:
            continue
        for right in range(left + 1, len(records)):
            group_a, group_b = records[left].group_id, records[right].group_id
            if group_a == group_b:
                continue
            b = shingles[right]
            if not b or min(len(a), len(b)) / max(len(a), len(b)) < threshold:
                continue
            overlap = len(a & b)
            if overlap / (len(a) + len(b) - overlap) >= threshold:
                near_pairs += 1
                cross_group_edges.add(tuple(sorted((group_a, group_b))))
                parents[find(group_b)] = find(group_a)

    components: dict[str, list[str]] = defaultdict(list)
    for group in groups:
        components[find(group)].append(group)
    canonical = {group: min(members) for members in components.values() for group in members}
    return [canonical[record.group_id] for record in records], {
        "provisional_groups": len(groups),
        "near_duplicate_pairs_across_groups": near_pairs,
        "near_duplicate_group_edges": len(cross_group_edges),
        "final_groups": len(components),
    }


def assign_splits(
    records: list[FunctionRecord], final_groups: list[str]
) -> tuple[list[str], dict[str, object]]:
    """Greedily fit complete groups to 70/15/15 sample-count targets."""

    if len(records) != len(final_groups) or not records:
        raise ValueError("record/group lengths must match and be nonempty")
    counts = Counter(final_groups)
    if len(counts) < 3:
        raise ValueError("at least three independent groups are required")
    targets = [share * len(records) for share in SPLIT_SHARES]
    sizes = [0, 0, 0]
    group_split: dict[str, int] = {}
    for group, size in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        choices = []
        for index in range(3):
            proposed = sizes.copy()
            proposed[index] += size
            squared_error = sum((actual - target) ** 2 for actual, target in zip(proposed, targets))
            choices.append((squared_error, index))
        chosen = min(choices)[1]
        group_split[group] = chosen
        sizes[chosen] += size
    splits = [SPLIT_NAMES[group_split[group]] for group in final_groups]
    if set(splits) != set(SPLIT_NAMES):
        raise ValueError("group sizes cannot populate all three splits")
    support = {
        name: dict(sorted(Counter(record.label for record, split in zip(records, splits) if split == name).items()))
        for name in SPLIT_NAMES
    }
    if any(set(class_counts) != {0, 1} for class_counts in support.values()):
        raise ValueError("each split must contain both classes")
    return splits, {
        "samples": dict(zip(SPLIT_NAMES, sizes)),
        "groups": dict(sorted(Counter(SPLIT_NAMES[index] for index in group_split.values()).items())),
        "class_support": support,
    }
