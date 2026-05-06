import json
import numpy as np
import joblib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / "models"


class AdaptiveEnsemble:
    """
    Three-layer hybrid classical/quantum ensemble classifier.

    Layer 1: Random Forest          — supervised, classical ML
    Layer 2: QSVM                   — supervised, quantum-enhanced ML
    Layer 3: Isolation Forest       — unsupervised, zero-day detection

    Decision logic:
        MALICIOUS          → supervised score > 0.80
        SUSPICIOUS         → supervised score > 0.50
        POTENTIAL_ZERO_DAY → supervised == SAFE and anomaly_score < θ
        SAFE               → otherwise

    Each layer degrades gracefully when its model file is absent.
    """

    def __init__(self):
        self.rf_available = False
        self.qsvm_available = False
        self.anomaly_available = False
        self.qsvm_feature_indices = None

        # Layer 1 — Random Forest
        try:
            self.scaler = joblib.load(MODEL_DIR / "scaler.pkl")
            self.rf_model = joblib.load(MODEL_DIR / "rf_model.pkl")
            self.rf_available = True
            logger.info("Random Forest model loaded successfully")
        except FileNotFoundError:
            logger.warning("RF model files not found — classical mode disabled")
        except Exception as e:
            logger.error(f"Failed to load RF model: {e}")

        # Layer 2 — QSVM (requires feature index map from RF training)
        try:
            with open(MODEL_DIR / "rf_feature_importances.json") as f:
                importances = json.load(f)
            self.qsvm_feature_indices = importances["top4_indices_in_feature_cols"]
        except Exception as e:
            logger.warning(f"Could not load QSVM feature indices: {e}")

        try:
            import sys
            from ai.train_qsvm import QuantumSVMPredictor
            if not hasattr(sys.modules.get("__main__", sys), "QuantumSVMPredictor"):
                setattr(sys.modules["__main__"], "QuantumSVMPredictor", QuantumSVMPredictor)

            self.qsvm_model = joblib.load(MODEL_DIR / "qsvm_model.pkl")
            if self.qsvm_feature_indices is not None:
                self.qsvm_available = True
                logger.info("QSVM model loaded successfully")
            else:
                logger.warning("QSVM loaded but feature indices missing — quantum mode disabled")
        except FileNotFoundError:
            logger.warning("QSVM model files not found — quantum mode disabled")
        except Exception as e:
            logger.error(f"Failed to load QSVM model: {e}")

        # Layer 3 — Isolation Forest (optional; missing file is not an error)
        try:
            self.if_model = joblib.load(MODEL_DIR / "if_model.pkl")
            with open(MODEL_DIR / "anomaly_threshold.json") as f:
                threshold_data = json.load(f)
            self.anomaly_threshold = threshold_data["theta"]
            self.anomaly_available = True
            logger.info("Isolation Forest loaded (θ=%.6f)", self.anomaly_threshold)
        except FileNotFoundError:
            logger.info("Isolation Forest not found — running in two-layer mode")
        except Exception as e:
            logger.error(f"Failed to load anomaly model: {e}")

    def _dynamic_weights(self, rf_score: float, qsvm_score: float) -> tuple[float, float]:
        """Return confidence-proportional weights for the two supervised models.

        Confidence = distance from the decision boundary (0.5).
        A model that outputs 0.95 contributes more than one that outputs 0.55.
        Falls back to (0.75, 0.25) when both scores are near 0.5.
        """
        rf_conf   = abs(rf_score   - 0.5) * 2   # [0, 1]
        qsvm_conf = abs(qsvm_score - 0.5) * 2
        total = rf_conf + qsvm_conf
        if total < 1e-9:
            return 0.75, 0.25
        return rf_conf / total, qsvm_conf / total

    def predict(self, feature_vector: np.ndarray) -> dict:
        """
        Run the three-layer ensemble prediction.

        Returns dict with: classification, final_score, rf_score, qsvm_score,
                           anomaly_score, is_potential_zero_day, mode
        """
        if not self.rf_available:
            logger.warning("No ML models available, cannot run ensemble prediction")
            return {
                "classification": "UNKNOWN",
                "final_score": 0.0,
                "rf_score": None,
                "qsvm_score": None,
                "anomaly_score": None,
                "is_potential_zero_day": False,
                "mode": "no_models",
            }

        # --- Layer 1: Random Forest ---
        try:
            X_sc = self.scaler.transform([feature_vector])
            rf_score = float(self.rf_model.predict_proba(X_sc)[0][1])
        except Exception as e:
            logger.error(f"RF prediction failed: {e}")
            return {
                "classification": "UNKNOWN",
                "final_score": 0.0,
                "rf_score": None,
                "qsvm_score": None,
                "anomaly_score": None,
                "is_potential_zero_day": False,
                "mode": "prediction_error",
            }

        # --- Layer 2: QSVM ---
        # X_sc is already scaled; select the 4 RF-importance-ranked features.
        # QuantumSVMPredictor.predict_proba() returns calibrated probabilities
        # via Platt scaling — no raw decision_function + expit hack needed.
        qsvm_score = None
        mode = "classical_only"

        if self.qsvm_available:
            try:
                X_q = X_sc[:, self.qsvm_feature_indices]
                qsvm_score = float(self.qsvm_model.predict_proba(X_q)[0][1])
                rf_w, qsvm_w = self._dynamic_weights(rf_score, qsvm_score)
                final_score = rf_w * rf_score + qsvm_w * qsvm_score
                mode = "hybrid"
            except Exception as e:
                logger.warning(f"QSVM prediction failed, using classical fallback: {e}")
                final_score = rf_score
                mode = "classical_fallback"
        else:
            final_score = rf_score

        # Supervised classification thresholds
        if final_score > 0.80:
            classification = "MALICIOUS"
        elif final_score > 0.50:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        # --- Layer 3: Isolation Forest (sequential override, SAFE events only) ---
        # sklearn decision_function: positive = normal, negative = anomaly.
        # Override to POTENTIAL_ZERO_DAY only when supervised said SAFE and
        # the anomaly score falls below the calibrated threshold θ.
        anomaly_score = None
        is_potential_zero_day = False

        if self.anomaly_available:
            try:
                anomaly_score = float(self.if_model.decision_function(X_sc)[0])
                if classification == "SAFE" and anomaly_score < self.anomaly_threshold:
                    classification = "POTENTIAL_ZERO_DAY"
                    is_potential_zero_day = True
            except Exception as e:
                logger.warning(f"Anomaly detection failed, skipping Layer 3: {e}")

        return {
            "classification": classification,
            "final_score": float(round(final_score, 4)),
            "rf_score": float(round(rf_score, 4)),
            "qsvm_score": float(round(qsvm_score, 4)) if qsvm_score is not None else None,
            "anomaly_score": float(round(anomaly_score, 6)) if anomaly_score is not None else None,
            "is_potential_zero_day": is_potential_zero_day,
            "mode": mode,
        }