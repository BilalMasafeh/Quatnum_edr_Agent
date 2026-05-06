"""
train_anomaly.py — Layer 3: Isolation Forest Anomaly Detector

Trains an unsupervised anomaly detector on benign-only data.
Computes anomaly threshold θ from calibration set so that FPR ≤ 5% (NFR-03).

Decision logic in the three-layer pipeline:
    supervised == SAFE and anomaly_score > θ  →  POTENTIAL_ZERO_DAY
    otherwise                                 →  supervised label unchanged

sklearn IsolationForest.decision_function() convention:
    positive score  →  normal (inlier)
    negative score  →  anomaly (outlier)
So anomaly condition is: score < threshold (threshold is negative, near 0).
θ is the 5th percentile of benign calibration scores, meaning 95% of benign
events score above θ, giving FPR ≤ 5% on the calibration distribution.

Inputs (from train_rf.py artifacts):
    backend/ai/models/X_train.pkl, X_cal.pkl, X_test.pkl
    backend/ai/models/y_train.pkl, y_cal.pkl,  y_test.pkl
    backend/ai/models/scaler.pkl

Outputs:
    backend/ai/models/if_model.pkl           — serialized IsolationForest
    backend/ai/models/anomaly_threshold.json — {"theta": float, "percentile": 5}
    backend/reports/anomaly_metrics.json     — evaluation results
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT.parent / "reports"

SPLITS = {
    "X_train": MODELS_DIR / "X_train.pkl",
    "X_cal":   MODELS_DIR / "X_cal.pkl",
    "X_test":  MODELS_DIR / "X_test.pkl",
    "y_train": MODELS_DIR / "y_train.pkl",
    "y_cal":   MODELS_DIR / "y_cal.pkl",
    "y_test":  MODELS_DIR / "y_test.pkl",
    "scaler":  MODELS_DIR / "scaler.pkl",
}

IF_MODEL_PATH      = MODELS_DIR / "if_model.pkl"
THRESHOLD_PATH     = MODELS_DIR / "anomaly_threshold.json"
METRICS_PATH       = REPORTS_DIR / "anomaly_metrics.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
N_ESTIMATORS    = 200
# contamination='auto' sets the offset so decision_function threshold = 0.
# We override the actual decision boundary with our calibrated θ, so this
# setting only affects the internal offset — does not hardcode FPR.
CONTAMINATION   = "auto"
RANDOM_STATE    = 42
# θ targets this percentile of benign calibration scores as the lower bound.
# 5th percentile means 95% of benign events score ≥ θ  →  FPR ≤ 5% (NFR-03).
BENIGN_PERCENTILE = 5
BENIGN_LABEL    = 0   # CICIDS2017: 0 = BENIGN

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Data loading
# ---------------------------------------------------------------------------

def load_splits() -> dict[str, np.ndarray]:
    log.info("Loading train/cal/test splits from %s", MODELS_DIR)
    for name, path in SPLITS.items():
        if not path.exists():
            log.error("Missing artifact: %s", path)
            log.error("Run train_rf.py first to generate splits and scaler.")
            sys.exit(1)

    data = {name: joblib.load(path) for name, path in SPLITS.items()}
    log.info(
        "Loaded — X_train %s  X_cal %s  X_test %s",
        data["X_train"].shape,
        data["X_cal"].shape,
        data["X_test"].shape,
    )
    return data


# ---------------------------------------------------------------------------
# 2. Feature scaling (reuse scaler from train_rf.py)
# ---------------------------------------------------------------------------

def scale_splits(
    scaler,
    X_train: np.ndarray,
    X_cal: np.ndarray,
    X_test: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Apply the RF-fitted scaler. Scaler is NOT re-fitted here — the anomaly
    detector must operate in the same feature space as the supervised models."""
    X_train_sc = scaler.transform(X_train)
    X_cal_sc   = scaler.transform(X_cal)
    X_test_sc  = scaler.transform(X_test)
    log.info("Features scaled with pre-fitted RF scaler (no re-fit).")
    return X_train_sc, X_cal_sc, X_test_sc


# ---------------------------------------------------------------------------
# 3. Filter benign samples
# ---------------------------------------------------------------------------

def filter_benign(X: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Return only rows where label == BENIGN (0).

    Isolation Forest is unsupervised and trains on the normal distribution.
    Including attack samples would shift the learned boundary and increase FPR.
    """
    mask = y == BENIGN_LABEL
    X_benign = X[mask]
    log.info(
        "Benign filter: %d / %d samples kept (%.1f%%)",
        X_benign.shape[0],
        X.shape[0],
        100 * X_benign.shape[0] / X.shape[0],
    )
    return X_benign


# ---------------------------------------------------------------------------
# 4. Train Isolation Forest
# ---------------------------------------------------------------------------

def train_isolation_forest(X_train_benign_sc: np.ndarray) -> IsolationForest:
    log.info(
        "Training IsolationForest — n_estimators=%d  contamination=%s  n_samples=%d",
        N_ESTIMATORS,
        CONTAMINATION,
        X_train_benign_sc.shape[0],
    )
    t0 = time.time()
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_benign_sc)
    elapsed = time.time() - t0
    log.info("Training complete in %.1fs", elapsed)
    return model


# ---------------------------------------------------------------------------
# 5. Compute threshold θ from calibration set
# ---------------------------------------------------------------------------

def compute_threshold(
    model: IsolationForest,
    X_cal_benign_sc: np.ndarray,
) -> float:
    """Calibrate θ so that FPR ≤ 5% on benign calibration data (NFR-03).

    sklearn decision_function: positive = normal, negative = anomaly.
    We take the 5th percentile of benign calibration scores as θ.
    95% of benign events score ≥ θ  →  FPR ≤ 5%.
    Any event scoring < θ is flagged POTENTIAL_ZERO_DAY.
    """
    scores = model.decision_function(X_cal_benign_sc)
    theta = float(np.percentile(scores, BENIGN_PERCENTILE))
    log.info(
        "Threshold θ = %.6f  (5th percentile of %d benign calibration scores)",
        theta,
        len(scores),
    )
    log.info(
        "Score stats — min=%.4f  p5=%.4f  median=%.4f  p95=%.4f  max=%.4f",
        scores.min(),
        np.percentile(scores, 5),
        np.median(scores),
        np.percentile(scores, 95),
        scores.max(),
    )
    return theta


# ---------------------------------------------------------------------------
# 6. Evaluate
# ---------------------------------------------------------------------------

def evaluate_anomaly(
    model: IsolationForest,
    theta: float,
    X_test_sc: np.ndarray,
    y_test: np.ndarray,
) -> dict:
    """Evaluate the anomaly detector on the held-out test set.

    Metrics:
    - FPR on benign (target: ≤ 5% per NFR-03)
    - Detection rate on attacks (recall for POTENTIAL_ZERO_DAY flag)
    - PR-AUC treating attack as positive class (using raw anomaly scores)

    Note: the anomaly detector is not a replacement for the supervised models.
    It only fires when supervised prediction == SAFE. These numbers reflect
    the detector's raw performance, not the final three-layer system FPR.
    """
    scores = model.decision_function(X_test_sc)
    # Anomaly flag: True when score < θ  →  POTENTIAL_ZERO_DAY candidate
    flagged = scores < theta

    benign_mask = y_test == BENIGN_LABEL
    attack_mask = ~benign_mask

    n_benign = benign_mask.sum()
    n_attack = attack_mask.sum()

    # FPR: fraction of benign events incorrectly flagged as anomalous
    false_positives = flagged[benign_mask].sum()
    fpr = float(false_positives / n_benign) if n_benign > 0 else 0.0

    # Detection rate: fraction of attacks flagged (recall on attack class)
    true_positives = flagged[attack_mask].sum()
    detection_rate = float(true_positives / n_attack) if n_attack > 0 else 0.0

    # PR-AUC: invert scores so higher = more anomalous (attack-positive convention)
    inverted_scores = -scores
    pr_auc = float(average_precision_score(attack_mask.astype(int), inverted_scores))

    log.info("--- Anomaly Detector Evaluation ---")
    log.info("  FPR on benign   : %.4f  (NFR-03 target ≤ 0.05)", fpr)
    log.info("  Detection rate  : %.4f  (attack recall)", detection_rate)
    log.info("  PR-AUC (attack) : %.4f", pr_auc)
    log.info("  n_benign=%d  n_attack=%d  flagged=%d", n_benign, n_attack, flagged.sum())

    if fpr > 0.05:
        log.warning(
            "FPR %.4f exceeds NFR-03 target (0.05). "
            "Consider tightening θ or reviewing calibration set composition.",
            fpr,
        )

    return {
        "fpr_on_benign":        fpr,
        "attack_detection_rate": detection_rate,
        "pr_auc_attack":        pr_auc,
        "n_test_benign":        int(n_benign),
        "n_test_attack":        int(n_attack),
        "n_flagged_total":      int(flagged.sum()),
        "threshold_theta":      theta,
        "nfr_03_met":           fpr <= 0.05,
    }


# ---------------------------------------------------------------------------
# 7. Save artifacts
# ---------------------------------------------------------------------------

def save_artifacts(model: IsolationForest, theta: float) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, IF_MODEL_PATH)
    log.info("Saved IsolationForest  → %s", IF_MODEL_PATH)

    threshold_data = {
        "theta":              theta,
        "percentile":         BENIGN_PERCENTILE,
        "sklearn_convention": (
            "decision_function positive = normal, negative = anomaly. "
            "Flag event as POTENTIAL_ZERO_DAY if score < theta."
        ),
        "nfr_03_target":      "FPR <= 0.05 on benign calibration data",
    }
    THRESHOLD_PATH.write_text(json.dumps(threshold_data, indent=2))
    log.info("Saved anomaly threshold → %s", THRESHOLD_PATH)


# ---------------------------------------------------------------------------
# 8. Save report
# ---------------------------------------------------------------------------

def save_report(metrics: dict, training_meta: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "model":        "IsolationForest",
        "layer":        3,
        "role":         "unsupervised zero-day detection",
        "architecture": {
            "three_layer_pipeline": [
                "Layer 1: Random Forest (supervised, classical ML)",
                "Layer 2: QSVM (supervised, quantum-enhanced ML)",
                "Layer 3: Isolation Forest (unsupervised, zero-day detection)",
            ],
            "decision_logic": (
                "MALICIOUS          → if supervised == MALICIOUS. "
                "SUSPICIOUS         → if supervised == SUSPICIOUS. "
                "POTENTIAL_ZERO_DAY → if supervised == SAFE and anomaly_score > θ. "
                "SAFE               → otherwise."
            ),
            "potential_zero_day_trigger": (
                "POTENTIAL_ZERO_DAY events automatically trigger full Gemini "
                "multi-stage analysis (Stage 2+ in agent.py). Unknown threats "
                "require deepest analysis available."
            ),
            "graceful_degradation": (
                "if_model.pkl missing at startup → system continues in two-layer "
                "mode. No exception raised."
            ),
        },
        "training_config": {
            "n_estimators":    N_ESTIMATORS,
            "contamination":   CONTAMINATION,
            "random_state":    RANDOM_STATE,
            "training_data":   "benign-only (CICIDS2017 BENIGN class, 70% split)",
            "calibration_data": "benign calibration set (10% split, benign rows only)",
        },
        "threshold_design": {
            "method":     f"{100 - BENIGN_PERCENTILE}th percentile of benign calibration scores",
            "rationale":  "Directly targets NFR-03 (FPR ≤ 5%) without hardcoding",
            "theta":      metrics["threshold_theta"],
        },
        "evaluation": metrics,
        "training_meta": training_meta,
    }

    METRICS_PATH.write_text(json.dumps(report, indent=2))
    log.info("Saved anomaly report   → %s", METRICS_PATH)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest anomaly detector (Layer 3)."
    )
    parser.add_argument(
        "--skip-eval",
        action="store_true",
        help="Skip evaluation on test set (useful for quick artifact generation).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    t_start = time.time()

    log.info("=== train_anomaly.py — Isolation Forest (Layer 3) ===")

    # 1. Load splits
    data = load_splits()
    X_train, X_cal, X_test = data["X_train"], data["X_cal"], data["X_test"]
    y_train, y_cal, y_test = data["y_train"], data["y_cal"], data["y_test"]
    scaler = data["scaler"]

    # 2. Scale with RF scaler (no re-fit)
    X_train_sc, X_cal_sc, X_test_sc = scale_splits(scaler, X_train, X_cal, X_test)

    # 3. Filter benign for training and calibration
    X_train_benign_sc = filter_benign(X_train_sc, y_train)
    X_cal_benign_sc   = filter_benign(X_cal_sc,   y_cal)

    # 4. Train
    model = train_isolation_forest(X_train_benign_sc)

    # 5. Compute threshold
    theta = compute_threshold(model, X_cal_benign_sc)

    # 6. Evaluate
    if args.skip_eval:
        log.info("--skip-eval set: skipping test-set evaluation.")
        metrics = {
            "fpr_on_benign":        None,
            "attack_detection_rate": None,
            "pr_auc_attack":        None,
            "n_test_benign":        None,
            "n_test_attack":        None,
            "n_flagged_total":      None,
            "threshold_theta":      theta,
            "nfr_03_met":           None,
            "note":                 "Evaluation skipped via --skip-eval flag.",
        }
    else:
        metrics = evaluate_anomaly(model, theta, X_test_sc, y_test)

    # 7. Save artifacts
    save_artifacts(model, theta)

    # 8. Save report
    elapsed_total = time.time() - t_start
    training_meta = {
        "training_time_seconds": round(elapsed_total, 1),
        "n_train_benign":        int(X_train_benign_sc.shape[0]),
        "n_cal_benign":          int(X_cal_benign_sc.shape[0]),
        "scaler_source":         str(SPLITS["scaler"]),
    }
    save_report(metrics, training_meta)

    log.info("=== Done in %.1fs ===", elapsed_total)

    if not args.skip_eval and not metrics["nfr_03_met"]:
        log.warning(
            "NFR-03 NOT MET: FPR=%.4f. Review calibration set or adjust percentile.",
            metrics["fpr_on_benign"],
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
