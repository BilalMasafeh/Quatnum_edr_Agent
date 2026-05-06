# Architecture Decision Record — Anomaly Detection Layer

**Date:** 2026-05-05
**Status:** Approved
**Author:** AI Engineer (ML Team)

---

## Context

The existing two-layer supervised pipeline (RF + QSVM) cannot detect zero-day or novel attack
patterns that fall outside the training distribution. An unsupervised anomaly detection layer
is required to address this gap without modifying the existing ensemble architecture.

---

## Decision: Isolation Forest as Optional Third Layer

**Chosen approach:** scikit-learn `IsolationForest`, serialized with joblib as `ai/models/if_model.pkl`.

Rejected alternatives:
- **Autoencoder** — requires TensorFlow/PyTorch, overkill for tabular feature vectors of 6–28 dimensions
- **One-Class SVM** — O(n²) training time, impractical on CICIDS2017 benign class size, poor scaling

---

## Integration Design

The anomaly layer is **additive and non-voting**. It does not participate in the ensemble
weighted average. It applies a sequential override only when supervised models return SAFE.

```
feature_vector
     ├──► AdaptiveEnsemble (RF + QSVM)  ──► supervised_classification
     └──► AnomalyDetector (IF)          ──► anomaly_score [0.0–1.0]

Final decision logic:
  MALICIOUS             → if supervised == MALICIOUS
  SUSPICIOUS            → if supervised == SUSPICIOUS
  POTENTIAL_ZERO_DAY    → if supervised == SAFE and anomaly_score > θ
  SAFE                  → otherwise
```

---

## Decisions

### Decision 1 — Availability
Optional with graceful degradation. If `if_model.pkl` is missing at startup,
system continues operating in two-layer mode. No exception raised. Matches QSVM pattern.

### Decision 2 — Threshold θ
Auto-calculated during training. θ = 95th percentile of anomaly scores on benign
calibration samples. This directly targets FPR ≤ 5% (NFR-03) without hardcoding.
θ is persisted alongside `if_model.pkl` (e.g., as a metadata JSON or inside the pkl).

### Decision 3 — Gemini Trigger
`POTENTIAL_ZERO_DAY` events automatically trigger the full Gemini multi-stage analysis
(Stage 2 onwards in `agent.py`). Rationale: unknown threats require the deepest analysis
available, and the supervised models explicitly failed to classify them.

---

## Impact on Other Components

| Component | Impact | Owner |
|---|---|---|
| `backend/ai/anomaly.py` | New file — AnomalyDetector class | AI Engineer |
| `backend/ai/ensemble.py` | No changes | AI Engineer |
| `backend/api/main.py` | Add anomaly call after ensemble in `/api/event` | AI Engineer |
| `backend/ai/models/if_model.pkl` | New model artifact from training script | AI Engineer |
| `database/models.py` | Add `anomaly_score FLOAT`, `is_potential_zero_day BOOLEAN` to Alert | Al-Abbas / AI Engineer |
| Frontend `App.js` | Handle `POTENTIAL_ZERO_DAY` in StatusBadge (suggest purple) | Al-Abbas / AI Engineer |

---

## Report Section

Architecture updated to **Three-Layer Detection**:
- Layer 1: Random Forest (supervised, classical ML)
- Layer 2: QSVM (supervised, quantum-enhanced ML)
- Layer 3: Isolation Forest (unsupervised, zero-day detection)

Ensemble section renamed: "Adaptive Ensemble Voting" → "Calibrated Adaptive Ensemble"
