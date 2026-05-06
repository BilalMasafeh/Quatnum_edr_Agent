"""
train_qsvm.py — Layer 2: Quantum Support Vector Machine

Trains a quantum kernel SVM on the 4 most important features identified by
the Random Forest (loaded from rf_feature_importances.json).

Computational constraint: quantum kernel evaluation is O(n²) in the number of
training samples. With n=2000 and a 4-qubit ZZFeatureMap, training takes
~60–90 minutes on CPU simulation. Use --subsample 200 for a quick test run
(~1–2 minutes).

Inputs (from train_rf.py artifacts):
    backend/ai/models/X_train.pkl, X_cal.pkl, X_test.pkl
    backend/ai/models/y_train.pkl, y_cal.pkl,  y_test.pkl
    backend/ai/models/scaler.pkl
    backend/ai/models/rf_feature_importances.json

Outputs:
    backend/ai/models/qsvm_model.pkl     — QuantumSVMPredictor (serializable)
    backend/reports/qsvm_metrics.json    — evaluation results
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
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.svm import SVC

from qiskit.circuit.library import ZZFeatureMap
from qiskit_machine_learning.kernels import FidelityQuantumKernel

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT.parent / "reports"

SPLITS = {
    "X_train":     MODELS_DIR / "X_train.pkl",
    "X_cal":       MODELS_DIR / "X_cal.pkl",
    "X_test":      MODELS_DIR / "X_test.pkl",
    "y_train":     MODELS_DIR / "y_train.pkl",
    "y_cal":       MODELS_DIR / "y_cal.pkl",
    "y_test":      MODELS_DIR / "y_test.pkl",
    "scaler":      MODELS_DIR / "scaler.pkl",
    "importances": MODELS_DIR / "rf_feature_importances.json",
}

QSVM_MODEL_PATH = MODELS_DIR / "qsvm_model.pkl"
METRICS_PATH    = REPORTS_DIR / "qsvm_metrics.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
N_QUBITS        = 4
REPS            = 2
TRAIN_SUBSAMPLE = 2000   # O(n²) kernel evaluations — ~60–90 min on CPU simulation
RANDOM_STATE    = 42

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
# QuantumSVMPredictor — serializable inference wrapper
# ---------------------------------------------------------------------------

class QuantumSVMPredictor:
    """Serializable QSVM inference object.

    Stores only lightweight numpy arrays — no Qiskit primitive objects that
    may fail to serialize with joblib. The quantum kernel is rebuilt from
    parameters at inference time.

    Stores support vectors only (not full training set) to keep inference fast:
    typically 5–15% of training samples, reducing kernel circuit evaluations
    from O(n_train) to O(n_sv) per prediction.
    """

    def __init__(
        self,
        support_vectors: np.ndarray,
        dual_coef: np.ndarray,
        intercept: np.ndarray,
        platt_a: float,
        platt_b: float,
        feature_indices: list[int],
        n_qubits: int,
        reps: int,
    ):
        self.support_vectors = support_vectors
        self.dual_coef       = dual_coef
        self.intercept       = intercept
        self.platt_a         = platt_a
        self.platt_b         = platt_b
        self.feature_indices = feature_indices
        self.n_qubits        = n_qubits
        self.reps            = reps

    def _build_kernel(self) -> FidelityQuantumKernel:
        feature_map = ZZFeatureMap(feature_dimension=self.n_qubits, reps=self.reps)
        return FidelityQuantumKernel(feature_map=feature_map)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        kernel = self._build_kernel()
        K = kernel.evaluate(x_vec=X, y_vec=self.support_vectors)
        return (K @ self.dual_coef.T).ravel() + self.intercept[0]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        scores = self.decision_function(X)
        prob_attack = expit(self.platt_a * scores + self.platt_b)
        return np.column_stack([1 - prob_attack, prob_attack])

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.decision_function(X) >= 0).astype(int)


# ---------------------------------------------------------------------------
# 1. Data loading
# ---------------------------------------------------------------------------

def load_splits() -> dict:
    log.info("Loading train/cal/test splits from %s", MODELS_DIR)
    for name, path in SPLITS.items():
        if not path.exists():
            log.error("Missing artifact: %s", path)
            log.error("Run train_rf.py first to generate splits and scaler.")
            sys.exit(1)

    data = {}
    for name, path in SPLITS.items():
        if name == "importances":
            with open(path) as f:
                data[name] = json.load(f)
        else:
            data[name] = joblib.load(path)

    log.info(
        "Loaded — X_train %s  X_cal %s  X_test %s",
        data["X_train"].shape,
        data["X_cal"].shape,
        data["X_test"].shape,
    )
    return data


# ---------------------------------------------------------------------------
# 2. Load feature indices from RF importance ranking
# ---------------------------------------------------------------------------

def load_feature_indices(importances: dict) -> tuple[list[int], list[str]]:
    """Return the top-4 feature indices and names selected by RF importance.

    These are indices into the 6-column feature space from feature_extractor.py,
    NOT into the original CICIDS2017 column order. The same indices are used in
    ensemble.py for consistent feature selection at inference time.
    """
    indices = importances["top4_indices_in_feature_cols"]
    names   = importances["top4_for_qsvm"]
    log.info("QSVM feature indices (RF-ranked): %s", indices)
    log.info("QSVM feature names:               %s", names)
    return indices, names


# ---------------------------------------------------------------------------
# 3. Scale and select features
# ---------------------------------------------------------------------------

def prepare_features(
    scaler,
    feature_indices: list[int],
    X_train: np.ndarray,
    X_cal: np.ndarray,
    X_test: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Scale with RF scaler (no re-fit), then select the 4 quantum features."""
    X_train_sc = scaler.transform(X_train)[:, feature_indices]
    X_cal_sc   = scaler.transform(X_cal)[:, feature_indices]
    X_test_sc  = scaler.transform(X_test)[:, feature_indices]
    log.info(
        "Feature matrix after selection — train %s  cal %s  test %s",
        X_train_sc.shape, X_cal_sc.shape, X_test_sc.shape,
    )
    return X_train_sc, X_cal_sc, X_test_sc


# ---------------------------------------------------------------------------
# 4. Stratified subsample
# ---------------------------------------------------------------------------

def subsample_stratified(
    X: np.ndarray, y: np.ndarray, n: int = TRAIN_SUBSAMPLE
) -> tuple[np.ndarray, np.ndarray]:
    """Return a stratified random subsample of at most n rows.

    Stratification preserves the class ratio from the full training set.
    Required because quantum kernel evaluation is O(n²) — 2000 samples
    already takes ~60–90 minutes on CPU simulation.
    """
    if len(X) <= n:
        log.info("Training set (%d rows) ≤ subsample limit — using full set.", len(X))
        return X, y

    rng = np.random.default_rng(RANDOM_STATE)
    classes, counts = np.unique(y, return_counts=True)
    ratios = counts / len(y)
    indices = []
    for cls, ratio in zip(classes, ratios):
        cls_idx = np.where(y == cls)[0]
        n_cls = max(1, round(n * ratio))
        chosen = rng.choice(cls_idx, size=min(n_cls, len(cls_idx)), replace=False)
        indices.append(chosen)

    indices = np.concatenate(indices)
    rng.shuffle(indices)
    log.info(
        "Stratified subsample: %d → %d (ratio preserved, seed=%d)",
        len(X), len(indices), RANDOM_STATE,
    )
    return X[indices], y[indices]


# ---------------------------------------------------------------------------
# 5. Build quantum kernel
# ---------------------------------------------------------------------------

def build_quantum_kernel() -> FidelityQuantumKernel:
    feature_map = ZZFeatureMap(feature_dimension=N_QUBITS, reps=REPS)
    kernel = FidelityQuantumKernel(feature_map=feature_map)
    log.info("Quantum kernel: ZZFeatureMap(%d qubits, %d reps)", N_QUBITS, REPS)
    return kernel


# ---------------------------------------------------------------------------
# 6. Compute kernel matrix and train SVC
# ---------------------------------------------------------------------------

def train_svc(
    kernel: FidelityQuantumKernel,
    X_train_sub: np.ndarray,
    y_train_sub: np.ndarray,
) -> SVC:
    log.info(
        "Computing kernel matrix (%d × %d) — slow step (~60–90 min for 2000 samples).",
        len(X_train_sub), len(X_train_sub),
    )
    t0 = time.time()
    K_train = kernel.evaluate(x_vec=X_train_sub)
    log.info("Kernel matrix computed in %.1fs", time.time() - t0)

    log.info("Training SVC with precomputed kernel...")
    svc = SVC(kernel="precomputed", class_weight="balanced", random_state=RANDOM_STATE)
    svc.fit(K_train, y_train_sub)
    n_sv = len(svc.support_)
    log.info(
        "SVC trained — %d support vectors (%.1f%% of training set)",
        n_sv, 100 * n_sv / len(X_train_sub),
    )
    return svc


# ---------------------------------------------------------------------------
# 7. Extract support vectors
# ---------------------------------------------------------------------------

def extract_support_vectors(
    svc: SVC, X_train_sub_sc: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Recover support vector feature arrays from the subsampled training data.

    svc.support_vectors_ is not populated with a precomputed kernel — only
    svc.support_ (indices into the training set) is available. We recover
    the feature vectors by indexing X_train_sub_sc directly.
    """
    sv_indices      = svc.support_
    support_vectors = X_train_sub_sc[sv_indices]
    dual_coef       = svc.dual_coef_
    intercept       = svc.intercept_
    log.info("Extracted %d support vectors from training set.", len(support_vectors))
    return support_vectors, dual_coef, intercept


# ---------------------------------------------------------------------------
# 8. Calibrate with Platt scaling
# ---------------------------------------------------------------------------

CAL_SUBSAMPLE = 2000   # kernel evaluations for Platt scaling: CAL_SUBSAMPLE × n_support_vectors


def calibrate_qsvm(
    kernel: FidelityQuantumKernel,
    X_cal_sc: np.ndarray,
    y_cal: np.ndarray,
    support_vectors: np.ndarray,
    dual_coef: np.ndarray,
    intercept: np.ndarray,
) -> tuple[float, float]:
    """Fit Platt scaling (logistic regression on decision scores) on the
    calibration set.

    Proper Platt: a and b are learned from calibration data.
    This replaces the naive approximation a=−1, b=0 (which assumes the SVM
    decision boundary is perfectly centered, which is never true in practice).

    The full calibration set (282k samples) would require ~46M quantum kernel
    evaluations against support vectors — hours of compute. We subsample
    CAL_SUBSAMPLE rows (stratified) which is sufficient for logistic regression
    to learn the two Platt parameters a and b.
    """
    if len(X_cal_sc) > CAL_SUBSAMPLE:
        n_original = len(X_cal_sc)
        rng = np.random.default_rng(RANDOM_STATE)
        classes, counts = np.unique(y_cal, return_counts=True)
        ratios = counts / len(y_cal)
        idx = []
        for cls, ratio in zip(classes, ratios):
            cls_idx = np.where(y_cal == cls)[0]
            n_cls = max(1, round(CAL_SUBSAMPLE * ratio))
            idx.append(rng.choice(cls_idx, size=min(n_cls, len(cls_idx)), replace=False))
        idx = np.concatenate(idx)
        X_cal_sc = X_cal_sc[idx]
        y_cal    = y_cal[idx]
        log.info(
            "Calibration subsample: %d → %d (stratified, seed=%d)",
            n_original, len(X_cal_sc), RANDOM_STATE,
        )

    log.info(
        "Computing calibration kernel (%d samples × %d support vectors)...",
        len(X_cal_sc), len(support_vectors),
    )
    t0 = time.time()
    K_cal = kernel.evaluate(x_vec=X_cal_sc, y_vec=support_vectors)
    scores_cal = (K_cal @ dual_coef.T).ravel() + intercept[0]
    log.info("Calibration kernel computed in %.1fs", time.time() - t0)

    lr = LogisticRegression(solver="lbfgs", max_iter=1000, random_state=RANDOM_STATE)
    lr.fit(scores_cal.reshape(-1, 1), y_cal)
    platt_a = float(lr.coef_[0][0])
    platt_b = float(lr.intercept_[0])
    log.info("Platt scaling fitted — a=%.4f  b=%.4f", platt_a, platt_b)
    return platt_a, platt_b


# ---------------------------------------------------------------------------
# 9. Evaluate
# ---------------------------------------------------------------------------

EVAL_SUBSAMPLE = 2000   # kernel evaluations for test metrics: EVAL_SUBSAMPLE × n_support_vectors


def evaluate(
    predictor: QuantumSVMPredictor,
    X_test_sc: np.ndarray,
    y_test: np.ndarray,
) -> dict:
    # Full test set (565k) × support vectors would require ~91M circuit evaluations.
    # Subsample stratified to EVAL_SUBSAMPLE for feasible approximate metrics.
    n_original = len(X_test_sc)
    if n_original > EVAL_SUBSAMPLE:
        rng = np.random.default_rng(RANDOM_STATE)
        classes, counts = np.unique(y_test, return_counts=True)
        ratios = counts / len(y_test)
        idx = []
        for cls, ratio in zip(classes, ratios):
            cls_idx = np.where(y_test == cls)[0]
            n_cls = max(1, round(EVAL_SUBSAMPLE * ratio))
            idx.append(rng.choice(cls_idx, size=min(n_cls, len(cls_idx)), replace=False))
        idx = np.concatenate(idx)
        X_test_sc = X_test_sc[idx]
        y_test    = y_test[idx]
        log.info(
            "Test subsample: %d → %d (stratified, seed=%d)",
            n_original, len(X_test_sc), RANDOM_STATE,
        )

    log.info("Evaluating on test set (%d samples)...", len(X_test_sc))
    t0 = time.time()
    y_proba = predictor.predict_proba(X_test_sc)[:, 1]
    y_pred  = predictor.predict(X_test_sc)
    elapsed = time.time() - t0

    pr_auc   = float(average_precision_score(y_test, y_proba))
    roc_auc  = float(roc_auc_score(y_test, y_proba))
    accuracy = float((y_pred == y_test).mean())

    log.info("--- QSVM Evaluation ---")
    log.info("  PR-AUC (attack) : %.4f", pr_auc)
    log.info("  ROC-AUC         : %.4f", roc_auc)
    log.info("  Accuracy        : %.4f", accuracy)
    log.info("  Eval time       : %.1fs", elapsed)

    return {
        "pr_auc_attack":     pr_auc,
        "roc_auc":           roc_auc,
        "accuracy":          accuracy,
        "eval_time_seconds": round(elapsed, 1),
        "n_test":            int(len(y_test)),
        "n_test_original":   int(n_original),
        "evaluation_methodology": (
            "Single train/cal/test split (70/10/20) from CICIDS2017. "
            "Cross-validation omitted: O(n²) kernel cost makes k-fold infeasible "
            "(~6–9 hours for 5-fold on CPU simulation). Test metrics computed on "
            f"a stratified subsample of {EVAL_SUBSAMPLE} from {n_original} test samples "
            "due to quantum kernel evaluation cost (~91M circuits for full set). "
            "Calibration likewise uses a 2000-sample stratified subsample."
        ),
    }


# ---------------------------------------------------------------------------
# 10. Save artifacts
# ---------------------------------------------------------------------------

def save_artifacts(predictor: QuantumSVMPredictor) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(predictor, QSVM_MODEL_PATH)
    log.info("Saved QuantumSVMPredictor → %s", QSVM_MODEL_PATH)


# ---------------------------------------------------------------------------
# 11. Save report
# ---------------------------------------------------------------------------

def save_report(metrics: dict, training_meta: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "model":  "QuantumSVM (ZZFeatureMap kernel, Platt-calibrated)",
        "layer":  2,
        "kernel": f"ZZFeatureMap({N_QUBITS} qubits, {REPS} reps) — FidelityQuantumKernel",
        "training_config": {
            "train_subsample":   TRAIN_SUBSAMPLE,
            "random_state":      RANDOM_STATE,
            "features":          training_meta.get("feature_names", []),
            "feature_indices":   training_meta.get("feature_indices", []),
            "n_support_vectors": training_meta.get("n_support_vectors"),
            "platt_a":           training_meta.get("platt_a"),
            "platt_b":           training_meta.get("platt_b"),
        },
        "evaluation":    metrics,
        "training_meta": training_meta,
    }
    METRICS_PATH.write_text(json.dumps(report, indent=2))
    log.info("Saved QSVM report → %s", METRICS_PATH)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train Quantum SVM (Layer 2).")
    parser.add_argument(
        "--subsample", type=int, default=TRAIN_SUBSAMPLE,
        help=(
            f"Number of training samples for kernel computation "
            f"(default: {TRAIN_SUBSAMPLE}). Use 200 for a quick test (~1–2 min)."
        ),
    )
    parser.add_argument(
        "--skip-eval", action="store_true",
        help="Skip test-set evaluation. Artifacts are saved; no metrics report written. "
             "Use with --subsample for a fast smoke-test of the pipeline.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    t_start = time.time()

    log.info("=== train_qsvm.py — Quantum SVM (Layer 2) ===")
    if args.subsample < TRAIN_SUBSAMPLE:
        log.warning(
            "--subsample=%d (full training uses %d). Results will be approximate.",
            args.subsample, TRAIN_SUBSAMPLE,
        )

    # 1. Load splits + importances
    data = load_splits()
    X_train, X_cal, X_test = data["X_train"], data["X_cal"], data["X_test"]
    y_train, y_cal, y_test = data["y_train"], data["y_cal"], data["y_test"]
    scaler = data["scaler"]

    # 2. Feature indices from RF importance ranking
    feature_indices, feature_names = load_feature_indices(data["importances"])

    # 3. Scale + select 4 quantum features
    X_train_sc, X_cal_sc, X_test_sc = prepare_features(
        scaler, feature_indices, X_train, X_cal, X_test
    )

    # 4. Stratified subsample (O(n²) constraint)
    X_train_sub, y_train_sub = subsample_stratified(X_train_sc, y_train, n=args.subsample)

    # 5. Build quantum kernel
    kernel = build_quantum_kernel()

    # 6. Compute kernel matrix + train SVC
    svc = train_svc(kernel, X_train_sub, y_train_sub)

    # 7. Extract support vectors (svc.support_vectors_ unavailable with precomputed kernel)
    support_vectors, dual_coef, intercept = extract_support_vectors(svc, X_train_sub)

    # 8. Platt calibration on calibration set
    platt_a, platt_b = calibrate_qsvm(
        kernel, X_cal_sc, y_cal, support_vectors, dual_coef, intercept,
    )

    # 9. Build serializable predictor (no Qiskit objects stored)
    predictor = QuantumSVMPredictor(
        support_vectors=support_vectors,
        dual_coef=dual_coef,
        intercept=intercept,
        platt_a=platt_a,
        platt_b=platt_b,
        feature_indices=feature_indices,
        n_qubits=N_QUBITS,
        reps=REPS,
    )

    # 10. Save artifacts first — evaluation may be slow or skipped
    save_artifacts(predictor)

    elapsed_total = time.time() - t_start
    training_meta = {
        "training_time_seconds": round(elapsed_total, 1),
        "subsample_used":        int(len(X_train_sub)),
        "n_support_vectors":     int(len(support_vectors)),
        "platt_a":               platt_a,
        "platt_b":               platt_b,
        "feature_names":         feature_names,
        "feature_indices":       feature_indices,
    }

    # 11. Evaluate (skippable for quick runs)
    if args.skip_eval:
        log.info("--skip-eval set: skipping test-set evaluation.")
        log.info("=== Done in %.1fs ===", elapsed_total)
        return

    metrics = evaluate(predictor, X_test_sc, y_test)
    save_report(metrics, training_meta)

    log.info("=== Done in %.1fs ===", elapsed_total)


if __name__ == "__main__":
    main()
