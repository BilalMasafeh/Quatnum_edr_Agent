"""
train_rf.py — Train and calibrate the Random Forest classifier on CICIDS2017.

Pipeline:
    1. Load & concatenate CICIDS2017 CSV files
    2. Preprocess: select 6 features, clean NaN/Inf, binary-encode labels
    3. 70 / 10 / 20 stratified split  (train / calibration / test)
    4. Fit StandardScaler on train only, apply to all splits
    5. Train RandomForest with class_weight='balanced'
    6. Calibrate with Platt scaling on calibration set (cv='prefit')
    7. 5-fold stratified CV on training set (scaler fitted per-fold — no leakage)
    8. Full evaluation on test set: accuracy, per-class metrics, ROC-AUC,
       PR-AUC, confusion matrix, FPR sweep for NFR-03, calibration curve data
    9. Save artifacts to ai/models/ and reports to reports/

Run from backend/ directory:
    python -m ai.train_rf
    python -m ai.train_rf --data-dir /path/to/CICIDS2017

Outputs (ai/models/):
    scaler.pkl            — StandardScaler fitted on training set
    rf_model.pkl          — CalibratedClassifierCV (Platt-scaled RF)
    rf_feature_importances.json  — feature importances (consumed by train_qsvm.py)
    X_train.pkl / X_cal.pkl / X_test.pkl   — unscaled feature splits
    y_train.pkl / y_cal.pkl / y_test.pkl   — label splits

Outputs (reports/):
    rf_metrics.json       — test set evaluation
    rf_cv_results.json    — 5-fold CV mean +/- std
"""

import argparse
import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler

# ── Paths ──────────────────────────────────────────────────────────────────────

MODEL_DIR = Path(__file__).parent / "models"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
DEFAULT_DATA_DIR = Path(__file__).parent / "data"

# ── Feature & Label Configuration ─────────────────────────────────────────────
#
# These 6 columns from CICIDS2017 are the ones approximated by event_to_features()
# in feature_extractor.py. Column names are stripped of whitespace on load.
#
FEATURE_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Fwd IAT Mean",
    "Destination Port",
]
LABEL_COL = "Label"
BENIGN_LABEL = "BENIGN"

# ── Hyperparameters ────────────────────────────────────────────────────────────

RF_PARAMS = dict(
    n_estimators=300,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42,
)
CV_FOLDS = 5
RANDOM_STATE = 42
FPR_TARGET = 0.05   # NFR-03: FPR must not exceed 5%

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Data Loading
# ══════════════════════════════════════════════════════════════════════════════

def load_cicids2017(data_dir: Path) -> pd.DataFrame:
    """
    Load and concatenate all CSV files in data_dir.
    Strips leading/trailing whitespace from column names (CICFlowMeter quirk).
    Raises FileNotFoundError if no CSVs are found.
    """
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}.\n"
            f"Download CICIDS2017 from the Canadian Institute for Cybersecurity "
            f"and place the CSV files in that directory."
        )

    logger.info(f"Found {len(csv_files)} CSV file(s) in {data_dir}")
    frames = []
    for path in csv_files:
        logger.info(f"  Loading {path.name}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    logger.info(f"Total records loaded: {len(combined):,}")
    return combined


# ══════════════════════════════════════════════════════════════════════════════
# 2. Preprocessing
# ══════════════════════════════════════════════════════════════════════════════

def preprocess(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Select FEATURE_COLS, clean infinite/NaN values, binary-encode labels.

    CICIDS2017 known issues handled here:
      - 'Flow Bytes/s' and 'Flow Packets/s' contain 'Infinity' strings
        from CICFlowMeter division-by-zero — coerced to NaN and dropped.
      - Some files have the header row duplicated mid-file — the to_numeric
        coercion turns those string values into NaN, which are then dropped.

    Returns:
        X : ndarray (n_samples, 6)  — raw unscaled features
        y : ndarray (n_samples,)    — 0 = BENIGN, 1 = ATTACK
    """
    required = FEATURE_COLS + [LABEL_COL]
    missing_cols = [c for c in required if c not in df.columns]
    if missing_cols:
        raise ValueError(
            f"Missing columns: {missing_cols}\n"
            f"Available columns: {list(df.columns[:20])} ..."
        )

    df = df[required].copy()

    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    n_before = len(df)
    df.dropna(inplace=True)
    n_dropped = n_before - len(df)
    if n_dropped > 0:
        logger.warning(
            f"Dropped {n_dropped:,} rows containing NaN/Inf "
            f"({n_dropped / n_before * 100:.2f}% of total)"
        )

    y = (df[LABEL_COL].str.strip() != BENIGN_LABEL).astype(np.int32).values
    X = df[FEATURE_COLS].values.astype(np.float64)

    n_attack = y.sum()
    n_benign = len(y) - n_attack
    logger.info(
        f"After preprocessing: {len(X):,} samples — "
        f"benign: {n_benign:,} ({n_benign/len(y)*100:.1f}%), "
        f"attack: {n_attack:,} ({n_attack/len(y)*100:.1f}%)"
    )
    return X, y


# ══════════════════════════════════════════════════════════════════════════════
# 3. Data Splitting
# ══════════════════════════════════════════════════════════════════════════════

def split_data(
    X: np.ndarray, y: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray,
           np.ndarray, np.ndarray, np.ndarray]:
    """
    Stratified 70 / 10 / 20 split.

    Strategy:
        1. Split off 20% test (stratified).
        2. From the remaining 80%, split off 12.5% as calibration
           (= 10% of the full dataset).

    Returns:
        X_train, X_cal, X_test, y_train, y_cal, y_test
        All arrays are UNSCALED — each downstream consumer applies its own scaler.
    """
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_temp, y_temp, test_size=0.125, stratify=y_temp, random_state=RANDOM_STATE
    )

    logger.info(
        f"Split — train: {len(X_train):,} | cal: {len(X_cal):,} | test: {len(X_test):,}"
    )
    return X_train, X_cal, X_test, y_train, y_cal, y_test


# ══════════════════════════════════════════════════════════════════════════════
# 4. Scaling
# ══════════════════════════════════════════════════════════════════════════════

def fit_scaler(
    X_train: np.ndarray, X_cal: np.ndarray, X_test: np.ndarray
) -> tuple[StandardScaler, np.ndarray, np.ndarray, np.ndarray]:
    """
    Fit StandardScaler exclusively on X_train, then transform all splits.
    X_cal and X_test are never seen during fit — no leakage.

    Returns:
        scaler, X_train_sc, X_cal_sc, X_test_sc
    """
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_cal_sc = scaler.transform(X_cal)
    X_test_sc = scaler.transform(X_test)
    logger.info("StandardScaler fitted on training set and applied to all splits")
    return scaler, X_train_sc, X_cal_sc, X_test_sc


# ══════════════════════════════════════════════════════════════════════════════
# 5. Training
# ══════════════════════════════════════════════════════════════════════════════

def train_rf(
    X_train_sc: np.ndarray, y_train: np.ndarray
) -> RandomForestClassifier:
    """
    Train RandomForestClassifier with class_weight='balanced'.
    class_weight compensates for the heavy class imbalance in CICIDS2017
    without requiring oversampling.
    """
    logger.info(f"Training RandomForest — params: {RF_PARAMS}")
    t0 = time.time()
    rf = RandomForestClassifier(**RF_PARAMS)
    rf.fit(X_train_sc, y_train)
    logger.info(f"Training complete in {time.time() - t0:.1f}s")
    return rf


# ══════════════════════════════════════════════════════════════════════════════
# 6. Calibration
# ══════════════════════════════════════════════════════════════════════════════

def calibrate_rf(
    rf: RandomForestClassifier,
    X_cal_sc: np.ndarray,
    y_cal: np.ndarray,
) -> CalibratedClassifierCV:
    """
    Apply Platt scaling to the already-fitted RF using the calibration set.

    cv='prefit' means sklearn treats 'rf' as already trained and only fits
    the sigmoid A, B parameters on (X_cal_sc, y_cal).

    After calibration, calibrated.predict_proba() returns true probabilities
    rather than the RF's raw leaf-fraction estimates (which tend toward 0.5).
    """
    logger.info("Calibrating RF with Platt scaling on calibration set (cv=None, prefit)")
    calibrated = CalibratedClassifierCV(estimator=rf, method="sigmoid", cv=None)
    calibrated.fit(X_cal_sc, y_cal)
    logger.info("Calibration complete")
    return calibrated


# ══════════════════════════════════════════════════════════════════════════════
# 7. Cross-Validation
# ══════════════════════════════════════════════════════════════════════════════

def run_cross_validation(
    X_train: np.ndarray, y_train: np.ndarray
) -> dict:
    """
    5-fold stratified CV on the raw (unscaled) training set.

    The scaler is fitted inside each fold's training portion to prevent
    leakage of validation statistics into the scaling step — a requirement
    for a clean evaluation. Each fold trains a fresh RF and evaluates on the
    held-out fold subset.

    Returns a dict of {metric: {"mean": float, "std": float}}.
    """
    logger.info(f"Starting {CV_FOLDS}-fold stratified cross-validation")
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    fold_results = {
        "accuracy":          [],
        "f1_macro":          [],
        "f1_attack":         [],
        "precision_attack":  [],
        "recall_attack":     [],
        "roc_auc":           [],
        "pr_auc":            [],
    }

    for fold_idx, (train_idx, val_idx) in enumerate(
        skf.split(X_train, y_train), start=1
    ):
        X_fold_tr, X_fold_val = X_train[train_idx], X_train[val_idx]
        y_fold_tr, y_fold_val = y_train[train_idx], y_train[val_idx]

        # Scale inside fold — scaler fitted only on fold training portion
        fold_scaler = StandardScaler()
        X_fold_tr = fold_scaler.fit_transform(X_fold_tr)
        X_fold_val = fold_scaler.transform(X_fold_val)

        rf_fold = RandomForestClassifier(**RF_PARAMS)
        rf_fold.fit(X_fold_tr, y_fold_tr)

        y_pred = rf_fold.predict(X_fold_val)
        y_proba = rf_fold.predict_proba(X_fold_val)[:, 1]
        report = classification_report(
            y_fold_val, y_pred, output_dict=True, zero_division=0
        )

        fold_results["accuracy"].append(accuracy_score(y_fold_val, y_pred))
        fold_results["f1_macro"].append(
            f1_score(y_fold_val, y_pred, average="macro", zero_division=0)
        )
        fold_results["f1_attack"].append(report.get("1", {}).get("f1-score", 0.0))
        fold_results["precision_attack"].append(
            report.get("1", {}).get("precision", 0.0)
        )
        fold_results["recall_attack"].append(report.get("1", {}).get("recall", 0.0))
        fold_results["roc_auc"].append(roc_auc_score(y_fold_val, y_proba))
        fold_results["pr_auc"].append(average_precision_score(y_fold_val, y_proba))

        logger.info(
            f"  Fold {fold_idx}/{CV_FOLDS} — "
            f"acc={fold_results['accuracy'][-1]:.4f}  "
            f"recall_attack={fold_results['recall_attack'][-1]:.4f}  "
            f"pr_auc={fold_results['pr_auc'][-1]:.4f}"
        )

    cv_summary = {}
    for metric, values in fold_results.items():
        arr = np.array(values)
        cv_summary[metric] = {
            "mean": round(float(arr.mean()), 6),
            "std":  round(float(arr.std()),  6),
            "per_fold": [round(float(v), 6) for v in values],
        }

    logger.info("Cross-validation summary:")
    for metric, stats in cv_summary.items():
        logger.info(f"  {metric}: {stats['mean']:.4f} +/- {stats['std']:.4f}")

    return cv_summary


# ══════════════════════════════════════════════════════════════════════════════
# 8. Evaluation
# ══════════════════════════════════════════════════════════════════════════════

def evaluate(
    calibrated_rf: CalibratedClassifierCV,
    X_test_sc: np.ndarray,
    y_test: np.ndarray,
) -> dict:
    """
    Full evaluation on the held-out test set (never seen during training
    or calibration).

    Metrics computed:
      - Accuracy (with class-imbalance caveat logged)
      - Precision / Recall / F1 per class (BENIGN and ATTACK)
      - F1 Macro
      - ROC-AUC
      - PR-AUC for ATTACK class  (primary metric for imbalanced data)
      - Confusion matrix (raw counts + row-normalized percentages)
      - FPR at default threshold 0.5  (vs NFR-03 target)
      - Threshold sweep: FPR and Recall at 0.00..1.00 in steps of 0.01
      - NFR-03 compliant threshold: lowest value where FPR <= FPR_TARGET
      - Calibration curve data for reliability diagram
    """
    logger.info("Evaluating calibrated RF on test set")

    y_pred = calibrated_rf.predict(X_test_sc)
    y_proba = calibrated_rf.predict_proba(X_test_sc)[:, 1]

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr_default = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Threshold sweep for NFR-03 analysis
    thresholds = np.round(np.arange(0.00, 1.01, 0.01), 2)
    threshold_sweep = []
    nfr03_threshold = None

    for t in thresholds:
        y_pred_t = (y_proba >= t).astype(int)
        cm_t = confusion_matrix(y_test, y_pred_t, labels=[0, 1])
        tn_t = cm_t[0, 0]; fp_t = cm_t[0, 1]
        fn_t = cm_t[1, 0]; tp_t = cm_t[1, 1]
        fpr_t = fp_t / (fp_t + tn_t) if (fp_t + tn_t) > 0 else 0.0
        recall_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0.0
        threshold_sweep.append({
            "threshold": float(t),
            "fpr":    round(fpr_t, 5),
            "recall": round(recall_t, 5),
        })
        if nfr03_threshold is None and fpr_t <= FPR_TARGET:
            nfr03_threshold = float(t)

    # Calibration curve — data for reliability diagram
    frac_pos, mean_pred = calibration_curve(y_test, y_proba, n_bins=10)

    metrics = {
        "dataset": "CICIDS2017",
        "note": (
            "Accuracy alone is misleading on this imbalanced dataset. "
            "Primary metrics are Recall(attack) and PR-AUC."
        ),
        "test_samples":        int(len(y_test)),
        "attack_prevalence":   round(float(y_test.mean()), 6),
        "accuracy":            round(float(accuracy_score(y_test, y_pred)), 6),
        "f1_macro":            round(float(
            f1_score(y_test, y_pred, average="macro", zero_division=0)
        ), 6),
        "roc_auc":             round(float(roc_auc_score(y_test, y_proba)), 6),
        "pr_auc_attack":       round(float(average_precision_score(y_test, y_proba)), 6),
        "per_class": {
            "benign": {
                "precision": round(report.get("0", {}).get("precision", 0.0), 6),
                "recall":    round(report.get("0", {}).get("recall", 0.0), 6),
                "f1_score":  round(report.get("0", {}).get("f1-score", 0.0), 6),
                "support":   int(report.get("0", {}).get("support", 0)),
            },
            "attack": {
                "precision": round(report.get("1", {}).get("precision", 0.0), 6),
                "recall":    round(report.get("1", {}).get("recall", 0.0), 6),
                "f1_score":  round(report.get("1", {}).get("f1-score", 0.0), 6),
                "support":   int(report.get("1", {}).get("support", 0)),
            },
        },
        "confusion_matrix": {
            "raw": cm.tolist(),
            "normalized_by_true_class": np.where(
                cm.sum(axis=1, keepdims=True) > 0,
                (cm / cm.sum(axis=1, keepdims=True)),
                0.0
            ).round(4).tolist(),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        },
        "fpr": {
            "at_threshold_0.5":      round(fpr_default, 6),
            "nfr03_target":          FPR_TARGET,
            "nfr03_compliant_threshold": nfr03_threshold,
            "nfr03_met_at_default":  fpr_default <= FPR_TARGET,
        },
        "threshold_sweep":     threshold_sweep,
        "calibration_curve": {
            "fraction_of_positives": [round(v, 6) for v in frac_pos.tolist()],
            "mean_predicted_value":  [round(v, 6) for v in mean_pred.tolist()],
        },
    }

    _print_summary(metrics)
    return metrics


def _print_summary(m: dict) -> None:
    sep = "=" * 56
    print(f"\n{sep}")
    print("  RANDOM FOREST — TEST SET RESULTS")
    print(sep)
    print(f"  Samples        : {m['test_samples']:,}  "
          f"(attack prevalence: {m['attack_prevalence']*100:.1f}%)")
    print(f"  Accuracy       : {m['accuracy']:.4f}  (see note below)")
    print(f"  F1 Macro       : {m['f1_macro']:.4f}")
    print(f"  ROC-AUC        : {m['roc_auc']:.4f}")
    print(f"  PR-AUC         : {m['pr_auc_attack']:.4f}  <- primary metric")
    atk = m["per_class"]["attack"]
    print(f"\n  Attack class:")
    print(f"    Precision : {atk['precision']:.4f}")
    print(f"    Recall    : {atk['recall']:.4f}  <- most critical (missed attacks)")
    print(f"    F1        : {atk['f1_score']:.4f}")
    cm = m["confusion_matrix"]
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm['tn']:>8,}   FP={cm['fp']:>8,}")
    print(f"    FN={cm['fn']:>8,}   TP={cm['tp']:>8,}")
    fpr_info = m["fpr"]
    nfr_ok = "PASS" if fpr_info["nfr03_met_at_default"] else "FAIL"
    print(f"\n  FPR @ threshold 0.50 : {fpr_info['at_threshold_0.5']:.4f}  "
          f"[NFR-03 target <= {FPR_TARGET}] -> {nfr_ok}")
    if fpr_info["nfr03_compliant_threshold"] is not None:
        print(f"  Threshold for FPR <= {FPR_TARGET} : "
              f"{fpr_info['nfr03_compliant_threshold']:.2f}")
    else:
        print(f"  WARNING: No threshold achieves FPR <= {FPR_TARGET}")
    print(f"\n  Note: {m['note']}")
    print(f"{sep}\n")


# ══════════════════════════════════════════════════════════════════════════════
# 9. Persistence
# ══════════════════════════════════════════════════════════════════════════════

def save_artifacts(
    scaler: StandardScaler,
    calibrated_rf: CalibratedClassifierCV,
    rf: RandomForestClassifier,
    X_train: np.ndarray, X_cal: np.ndarray, X_test: np.ndarray,
    y_train: np.ndarray, y_cal: np.ndarray, y_test: np.ndarray,
) -> None:
    """
    Persist all model artifacts and data splits.

    X_train/cal/test are saved UNSCALED so that train_qsvm.py and
    train_anomaly.py can apply their own scalers to appropriate feature subsets.

    rf_feature_importances.json is consumed by train_qsvm.py to select the
    4 most informative features for the quantum kernel.
    """
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(scaler,        MODEL_DIR / "scaler.pkl")
    joblib.dump(calibrated_rf, MODEL_DIR / "rf_model.pkl")

    joblib.dump(X_train, MODEL_DIR / "X_train.pkl")
    joblib.dump(X_cal,   MODEL_DIR / "X_cal.pkl")
    joblib.dump(X_test,  MODEL_DIR / "X_test.pkl")
    joblib.dump(y_train, MODEL_DIR / "y_train.pkl")
    joblib.dump(y_cal,   MODEL_DIR / "y_cal.pkl")
    joblib.dump(y_test,  MODEL_DIR / "y_test.pkl")

    # Feature importances for train_qsvm.py
    importances = rf.feature_importances_.tolist()
    ranked = sorted(
        zip(FEATURE_COLS, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    fi_data = {
        "feature_cols":       FEATURE_COLS,
        "importances":        dict(zip(FEATURE_COLS, [round(v, 6) for v in importances])),
        "ranked":             [{"feature": f, "importance": round(i, 6)} for f, i in ranked],
        "top4_for_qsvm":      [f for f, _ in ranked[:4]],
        "top4_indices_in_feature_cols": [
            FEATURE_COLS.index(f) for f, _ in ranked[:4]
        ],
    }
    with open(MODEL_DIR / "rf_feature_importances.json", "w") as fh:
        json.dump(fi_data, fh, indent=2)

    logger.info(f"All artifacts saved to {MODEL_DIR}")
    logger.info(f"Top 4 features for QSVM: {fi_data['top4_for_qsvm']}")


class _NumpyEncoder(json.JSONEncoder):
    """Serialize numpy scalars (np.bool_, np.int64, np.float64, etc.) to native Python types."""
    def default(self, obj):
        if isinstance(obj, np.generic):
            return obj.item()
        return super().default(obj)


def save_report(metrics: dict, cv_results: dict) -> None:
    """Write rf_metrics.json and rf_cv_results.json to REPORTS_DIR."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(REPORTS_DIR / "rf_metrics.json", "w") as fh:
        json.dump(metrics, fh, indent=2, cls=_NumpyEncoder)
    with open(REPORTS_DIR / "rf_cv_results.json", "w") as fh:
        json.dump(cv_results, fh, indent=2, cls=_NumpyEncoder)

    logger.info(f"Reports saved to {REPORTS_DIR}")


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and calibrate Random Forest on CICIDS2017."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory containing CICIDS2017 CSV files (default: {DEFAULT_DATA_DIR})",
    )
    args = parser.parse_args()

    logger.info("Quantum EDR — RF Training Pipeline")
    logger.info(f"Data directory : {args.data_dir}")
    logger.info(f"Model directory: {MODEL_DIR}")
    logger.info(f"Reports        : {REPORTS_DIR}")
    t_pipeline = time.time()

    # 1-2: Load and preprocess
    df = load_cicids2017(args.data_dir)
    X, y = preprocess(df)
    del df  # free memory before splitting

    # 3: Split
    X_train, X_cal, X_test, y_train, y_cal, y_test = split_data(X, y)
    del X, y

    # 4: Scale
    scaler, X_train_sc, X_cal_sc, X_test_sc = fit_scaler(X_train, X_cal, X_test)

    # 5: Train
    rf = train_rf(X_train_sc, y_train)

    # 6: Calibrate
    calibrated_rf = calibrate_rf(rf, X_cal_sc, y_cal)

    # 7: Cross-validation (on unscaled X_train — scaler fitted per fold internally)
    cv_results = run_cross_validation(X_train, y_train)

    # 8: Evaluate on test set
    metrics = evaluate(calibrated_rf, X_test_sc, y_test)

    # 9: Save
    save_artifacts(
        scaler, calibrated_rf, rf,
        X_train, X_cal, X_test,
        y_train, y_cal, y_test,
    )
    save_report(metrics, cv_results)

    elapsed = time.time() - t_pipeline
    logger.info(f"Pipeline complete in {elapsed:.1f}s")
    logger.info(
        "Next steps: run train_qsvm.py then train_anomaly.py "
        "(both require the PKLs just saved)"
    )


if __name__ == "__main__":
    main()
