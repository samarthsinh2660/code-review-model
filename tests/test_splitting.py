"""Grouped splitting keeps pairs and near duplicates together."""

import unittest

from vulnscope.records import FunctionRecord
from vulnscope.splitting import assign_splits, group_near_duplicates


def record(group, code, label, index):
    return FunctionRecord(
        language="c", file_path=f"{group}/{index}.c", source_code=code,
        start_line=1, end_line=1, label=label, source_id=f"{group}:{index}",
        group_id=group, dataset_version="fixture", license_id="CC0-1.0",
    )


class SplittingTests(unittest.TestCase):
    def test_near_duplicate_links_provisional_groups(self):
        records = [
            record("A", "void bad() { x = 1; free(x); }", 1, 0),
            record("B", "void goodB2G() { x = 1; free(x); }", 0, 1),
            record("C", "void unrelated() { return; }", 1, 2),
        ]
        groups, summary = group_near_duplicates(records)
        self.assertEqual(groups[0], groups[1])
        self.assertNotEqual(groups[0], groups[2])
        self.assertEqual(summary["final_groups"], 2)

    def test_whole_groups_and_both_classes_in_each_split(self):
        records = [record(group, "void f() {}", label, f"{group}{label}") for group in "ABCDE" for label in (0, 1)]
        groups = [record.group_id for record in records]
        splits, summary = assign_splits(records, groups)
        for group in "ABCDE":
            self.assertEqual({split for record, split in zip(records, splits) if record.group_id == group},
                             {splits[groups.index(group)]})
        self.assertEqual(set(splits), {"train", "validation", "test"})
        self.assertEqual(sum(summary["samples"].values()), len(records))


if __name__ == "__main__":
    unittest.main()
