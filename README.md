# Quantum EDR

Quantum EDR is a next-generation Endpoint Detection and Response (EDR) platform built on a hybrid classical-quantum machine learning pipeline. It provides real-time threat detection, AI-driven behavioral analysis, and automated mitigation capabilities.

## Features

- **Three-Layer ML Detection Engine**: A sequential detection pipeline combining supervised and unsupervised machine learning:
  - Layer 1 — Random Forest (classical supervised, calibrated with Platt scaling)
  - Layer 2 — Quantum SVM with ZZFeatureMap kernel (quantum-enhanced supervised)
  - Layer 3 — Isolation Forest (unsupervised zero-day detection)
- **Zero-Day Detection**: Novel threats that bypass the supervised layers are flagged as `POTENTIAL_ZERO_DAY` and automatically escalated to deep AI analysis. The anomaly threshold is auto-calibrated to hold false-positive rate ≤ 5%.
- **AI Threat Analysis**: Deep behavioral analysis powered by Google Gemini, mapping threats to the MITRE ATT&CK framework and generating response recommendations.
- **Real-Time Monitoring**: WebSocket-powered live event stream for instant visibility into endpoint telemetry.
- **Campaign Correlation**: Cross-alert correlation to detect sophisticated multi-stage attack campaigns.
- **Automated Response**: Configurable automated remediation (process termination, network isolation, deep analysis trigger) based on classification severity.
- **Professional Desktop Application**: A high-performance Electron + React (Vite) native desktop app with a cybersecurity-focused dark theme and rich visualizations.

## Architecture

### System Components

**Backend API (Python / FastAPI)**
- Database: PostgreSQL (with SQLite fallback)
- Real-time Events: WebSockets
- ML Pipeline: `scikit-learn`, `qiskit`, `qiskit-machine-learning`, `qiskit-aer`
- AI Agent: Google Gemini API

**Frontend**
- Desktop App (primary): Electron + Vite + React 19, vanilla CSS design system
- Web UI (secondary): Create React App, Tailwind CSS

### ML Pipeline — Three-Layer Detection

```
Incoming Event (feature vector)
        │
        ├──► Layer 1: Random Forest ──────────────────────────────────┐
        │    CalibratedClassifierCV (Platt scaling)                   │
        │    Trained on CICIDS2017 (70/10/20 split)                   │
        │                                                             │
        ├──► Layer 2: Quantum SVM ────────────────────────────────────┤
        │    ZZFeatureMap (4 qubits, 2 reps) + FidelityQuantumKernel  │  Calibrated
        │    Top-4 RF-importance features, Platt-calibrated           │  Adaptive
        │                                                             │  Ensemble
        │    Dynamic confidence-weighted fusion of L1 + L2 ──────────►│
        │                                                             │
        └──► Layer 3: Isolation Forest ──► anomaly_score             ▼
             Trained on benign-only data        ┌─────────────────────────────┐
             θ = 95th pct of benign cal scores  │ supervised == MALICIOUS     │──► MALICIOUS
             (targets FPR ≤ 5%)                 │ supervised == SUSPICIOUS    │──► SUSPICIOUS
                                                │ supervised == SAFE          │
                                                │   AND anomaly_score < θ    │──► POTENTIAL_ZERO_DAY
                                                │ otherwise                   │──► SAFE
                                                └─────────────────────────────┘
```

`POTENTIAL_ZERO_DAY` events automatically trigger full Gemini multi-stage analysis. The Isolation Forest layer is optional — if `if_model.pkl` is absent at startup the system continues in two-layer mode.

### Classification Labels

| Label | Meaning |
|---|---|
| `MALICIOUS` | Supervised ensemble score > 0.80 — confirmed threat |
| `SUSPICIOUS` | Supervised ensemble score > 0.50 — requires investigation |
| `POTENTIAL_ZERO_DAY` | Supervised said SAFE but anomaly detector flagged as novel/unknown |
| `SAFE` | No threat detected |

## Setup Instructions

### Prerequisites

- Python 3.10+
- Node.js 18+
- PostgreSQL (optional — defaults to SQLite)
- Google Gemini API Key (required for AI analysis)

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set your `GEMINI_API_KEY`:

```
GEMINI_API_KEY=your_key_here
API_KEY=quantum-edr-dev-key
```

Start the API server:

```bash
python -m uvicorn api.main:app --reload
```

The API runs at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Training the Models

The three training scripts must be run in order — each script depends on artifacts produced by the previous one.

```bash
cd backend

# Layer 1 — Random Forest (~2–5 min)
# Produces: rf_model.pkl, scaler.pkl, rf_feature_importances.json,
#           X_train.pkl, X_cal.pkl, X_test.pkl, y_train.pkl, y_cal.pkl, y_test.pkl
python -m ai.train_rf

# Layer 2 — Quantum SVM (~60–90 min on CPU simulation)
# Produces: qsvm_model.pkl
# Use --subsample 200 for a quick test run (~2 min, approximate results)
python -m ai.train_qsvm
python -m ai.train_qsvm --subsample 200   # quick test

# Layer 3 — Isolation Forest (~1–2 min)
# Produces: if_model.pkl, anomaly_threshold.json
python -m ai.train_anomaly
```

Training data (CICIDS2017) must be placed in `backend/ai/data/` before running. The data directory is excluded from version control (see `.gitignore`).

Evaluation reports are written to `backend/reports/` after each training run.

### Desktop App Setup

```bash
cd frontend/desktop
npm install
npm run electron:dev      # development (Vite + Electron)
npm run electron:build    # production build
```

### Web UI Setup (secondary)

```bash
cd frontend/quantum-edr-ui
npm install
npm start
```

The web UI runs at `http://localhost:3000` and connects to the backend at `http://localhost:8000`.

## Documentation

The `docs/` folder contains technical specifications for the project:

| File | Contents |
|---|---|
| `docs/feature_requirements_v1.md` | 28-feature specification for the Sysmon/Logstash ingestion pipeline — sent to the ELK team |
| `docs/anomaly_layer_decisions.md` | Architecture Decision Record for the Isolation Forest (Layer 3) design |
| `docs/api_contract.md` | API contract for `POST /api/event` — format specification for the ELK pipeline integration |

## Security & Privacy

- All AI processing uses structured JSON outputs to prevent prompt injection.
- The API includes API Key authentication middleware (disabled in dev mode, enforced in production).
- No raw binary data is sent to external APIs — only structured telemetry and metadata are analyzed.
- Anomaly threshold is auto-calibrated from data to avoid hardcoded security boundaries.
