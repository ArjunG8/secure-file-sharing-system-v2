"""Evaluate the detector on SYNTHETIC data:  python -m app.modules.anomaly.evaluate

Trains on one synthetic dataset and scores a second, independently generated one.
These numbers only show the pipeline separates the synthetic attack profiles from the
synthetic normal profile; they are NOT evidence of real-world detection accuracy.
"""

import argparse

from app.modules.anomaly.features import extract_windows
from app.modules.anomaly.service import fit, score_windows
from app.modules.anomaly.synthetic import dataset


def evaluate(train_seed: int = 1, test_seed: int = 2, contamination: float = 0.05) -> dict:
    train_events, _ = dataset(train_seed)
    test_events, labels = dataset(test_seed)
    model = fit(extract_windows(train_events), contamination)
    windows = extract_windows(test_events)
    results = score_windows(model, windows)
    tp = fp = fn = tn = 0
    for window, (_score, flagged) in zip(windows, results, strict=True):
        actual = (window.user_id, window.window_start) in labels
        tp += flagged and actual
        fp += flagged and not actual
        fn += (not flagged) and actual
        tn += (not flagged) and not actual
    return {
        "windows": len(windows), "attacks": tp + fn, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--train-seed", type=int, default=1)
    parser.add_argument("--test-seed", type=int, default=2)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()
    m = evaluate(args.train_seed, args.test_seed, args.contamination)
    print("SYNTHETIC DATA - not a measure of real-world accuracy")
    for key, value in m.items():
        print(f"  {key:<20} {value:.3f}" if isinstance(value, float) else f"  {key:<20} {value}")


if __name__ == "__main__":
    main()
