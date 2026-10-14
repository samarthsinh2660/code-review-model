"""Measure the frozen C alert-budget policy on fresh remainder-2 projects."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.evaluate_big_vul_holdout import run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/processed/big_vul_budget_test.jsonl"))
    parser.add_argument("--test-audit", type=Path, default=Path("data/processed/big_vul_budget_test_audit.json"))
    parser.add_argument("--train-audit", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--policy", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1/alert_policy_5pct.json"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/big_vul_c_budget_holdout_v1.json"))
    args = parser.parse_args()
    result = run(args.source, args.test_audit, args.train_audit, args.prepared_dir,
                 args.model_dir, args.result, policy_path=args.policy)
    print(json.dumps({key: value for key, value in result.items() if key not in {"predictions", "by_repository"}},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
