"""
Quantum EDR API — FastAPI Backend
Hybrid classical/quantum ML-based Endpoint Detection & Response system.
"""

import os
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent.parent / ".env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("quantum_edr")

# Imports (no more sys.path hacks — run from backend/ directory)
from database.database import get_db, init_db
from database.models import Alert, Response, Report, ThreatAnalysis
from ai.ensemble import AdaptiveEnsemble
from ai.feature_extractor import event_to_features
from ai.agent import analyze_threat, quick_analyze
from ai.threat_intel import analyze_behavior


# ── WebSocket Manager ──────────────────────────────────────
class ConnectionManager:
    """Manages WebSocket connections for real-time alert push."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.active_connections.remove(d)


ws_manager = ConnectionManager()


# ── Lifespan ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown logic."""
    init_db()
    logger.info("✓ Database initialized")
    logger.info(f"✓ ML Engine: RF={'loaded' if engine.rf_available else 'unavailable'}, QSVM={'loaded' if engine.qsvm_available else 'unavailable'}, AnomalyLayer={'loaded' if engine.anomaly_available else 'unavailable'}")
    logger.info("✓ Quantum EDR API Started!")
    yield
    logger.info("Quantum EDR API shutting down")


# ── App & Engine ───────────────────────────────────────────
engine = AdaptiveEnsemble()

app = FastAPI(
    title="Quantum EDR API",
    description="Hybrid Classical/Quantum ML Endpoint Detection & Response",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Key Auth ───────────────────────────────────────────
API_KEY = os.getenv("API_KEY", "quantum-edr-dev-key")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(api_key_header)):
    """Verify API key. In dev mode, allows requests without key."""
    if os.getenv("ENV", "development") == "production":
        if not api_key or api_key != API_KEY:
            raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return api_key


# ── Schemas ────────────────────────────────────────────────
class EventInput(BaseModel):
    process_name: str
    pid: int
    parent_process: str
    network_connections: int = 0
    file_writes: int = 0
    registry_changes: int = 0
    child_processes: int = 0
    unique_ips: int = 0
    suspicious_ports: int = 0


class ResponseAction(BaseModel):
    alert_id: int
    action_type: str
    details: str = ""


class AlertUpdate(BaseModel):
    status: str  # open, resolved, dismissed, escalated


# ── Routes ─────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "status": "Quantum EDR Running",
        "version": "2.0.0",
        "mode": "hybrid" if engine.qsvm_available else "classical"
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """System health check — verifies DB, ML models, and services."""
    # DB check
    db_ok = False
    try:
        db.execute(db.bind.dialect.do_execute if hasattr(db.bind, 'dialect') else None)
        db_ok = True
    except Exception:
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False

    # ES check
    es_ok = False
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(f"http://{os.getenv('ES_HOST', 'localhost')}:{os.getenv('ES_PORT', '9200')}")
        es_ok = es.ping()
    except Exception:
        es_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "components": {
            "api": True,
            "database": db_ok,
            "elasticsearch": es_ok,
            "rf_model": engine.rf_available,
            "qsvm_model": engine.qsvm_available,
            "ai_agent": bool(os.getenv("GEMINI_API_KEY")),
        },
        "mode": "hybrid" if engine.qsvm_available else ("classical" if engine.rf_available else "rule_based"),
        "websocket_connections": len(ws_manager.active_connections)
    }


@app.get("/status")
def status():
    return {
        "api": "online",
        "quantum": engine.qsvm_available,
        "classical": engine.rf_available,
        "mode": "hybrid" if engine.qsvm_available else ("classical" if engine.rf_available else "rule_based")
    }


@app.post("/api/event")
async def receive_event(
    event: EventInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Receive a security event, run ML classification, and create an alert.
    Uses the AdaptiveEnsemble when models are available, falls back to rules.
    """
    event_data = event.model_dump()

    # Use ML ensemble if available, otherwise fall back to rules
    if engine.rf_available:
        try:
            features = event_to_features(event_data)
            result = engine.predict(features)
            logger.info(f"ML prediction: {result['classification']} (score={result['final_score']}, mode={result['mode']})")
        except Exception as e:
            logger.error(f"ML prediction failed, falling back to rules: {e}")
            result = _rule_based_score(event_data)
    else:
        result = _rule_based_score(event_data)

    # Quick behavioral analysis (no AI calls, instant)
    behavior = quick_analyze(event_data)

    # Save alert with full event data
    alert = Alert(
        timestamp=datetime.now(),
        process_name=event.process_name,
        pid=event.pid,
        parent_process=event.parent_process,
        classification=result["classification"],
        final_score=result["final_score"],
        rf_score=result["rf_score"],
        qsvm_score=result["qsvm_score"],
        anomaly_score=result["anomaly_score"],
        is_potential_zero_day=result["is_potential_zero_day"],
        mode=result["mode"],
        status="open",
        network_connections=event.network_connections,
        file_writes=event.file_writes,
        registry_changes=event.registry_changes,
        child_processes=event.child_processes,
        unique_ips=event.unique_ips,
        suspicious_ports=event.suspicious_ports,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if result["is_potential_zero_day"]:
        background_tasks.add_task(_trigger_gemini_analysis, alert.id)

    # Auto-response
    response_action = _determine_response(result["classification"])
    response = Response(
        alert_id=alert.id,
        action_type=response_action,
        timestamp=datetime.now(),
        success=True,
        details=f"Auto response: {response_action}"
    )
    db.add(response)
    db.commit()

    # Broadcast to WebSocket clients
    ws_message = {
        "type": "new_alert",
        "alert_id": alert.id,
        "process": event.process_name,
        "classification": result["classification"],
        "score": result["final_score"],
        "mode": result["mode"],
        "action": response_action,
        "timestamp": datetime.now().isoformat(),
        "behavioral_risk": behavior.get("risk_score", 0),
        "indicators": behavior.get("indicators", []),
        "anomaly_score": result["anomaly_score"],
        "is_potential_zero_day": result["is_potential_zero_day"],
    }
    await ws_manager.broadcast(ws_message)

    return {
        "alert_id": alert.id,
        "process": event.process_name,
        "result": result,
        "action": response_action,
        "behavioral_indicators": behavior.get("indicators", []),
        "behavioral_risk": behavior.get("risk_score", 0)
    }


@app.get("/api/alerts")
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    classification: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Get alerts with pagination and filtering."""
    query = db.query(Alert).order_by(Alert.timestamp.desc())

    if classification:
        query = query.filter(Alert.classification == classification.upper())
    if status:
        query = query.filter(Alert.status == status)

    total = query.count()
    alerts = query.offset(skip).limit(limit).all()

    return {
        "alerts": alerts,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    responses = db.query(Response).filter(Response.alert_id == alert_id).all()
    analyses = db.query(ThreatAnalysis).filter(ThreatAnalysis.alert_id == alert_id).all()

    return {
        "alert": alert,
        "responses": responses,
        "analyses": analyses
    }


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    """Update alert status (resolve, dismiss, escalate)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = update.status
    db.commit()
    return {"status": "updated", "alert_id": alert_id, "new_status": update.status}


@app.post("/api/respond")
def manual_respond(action: ResponseAction, db: Session = Depends(get_db)):
    """Record a manual response action on an alert."""
    # Verify alert exists
    alert = db.query(Alert).filter(Alert.id == action.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    response = Response(
        alert_id=action.alert_id,
        action_type=action.action_type,
        timestamp=datetime.now(),
        success=True,
        details=action.details
    )
    db.add(response)
    db.commit()
    return {"status": "Response executed", "action": action.action_type}


@app.post("/api/analyze/{alert_id}")
def ai_analyze(alert_id: int, db: Session = Depends(get_db)):
    """
    Run full multi-stage AI analysis on an alert.
    Returns behavioral analysis, threat classification, MITRE mapping,
    response recommendations, and incident report.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Get recent alerts for correlation
    recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
    recent_dicts = []
    for a in recent_alerts:
        recent_dicts.append({
            "id": a.id,
            "process_name": a.process_name,
            "pid": a.pid,
            "parent_process": a.parent_process,
            "classification": a.classification,
            "final_score": a.final_score,
            "timestamp": a.timestamp,
            "network_connections": a.network_connections,
            "file_writes": a.file_writes,
            "registry_changes": a.registry_changes,
            "child_processes": a.child_processes,
            "unique_ips": a.unique_ips,
            "suspicious_ports": a.suspicious_ports,
        })

    # Build alert dict
    alert_dict = {
        "id": alert.id,
        "process_name": alert.process_name,
        "pid": alert.pid,
        "parent_process": alert.parent_process,
        "classification": alert.classification,
        "final_score": alert.final_score,
        "mode": alert.mode,
        "network_connections": alert.network_connections,
        "file_writes": alert.file_writes,
        "registry_changes": alert.registry_changes,
        "child_processes": alert.child_processes,
        "unique_ips": alert.unique_ips,
        "suspicious_ports": alert.suspicious_ports,
    }

    # Run full AI analysis
    analysis = analyze_threat(alert_dict, recent_dicts)

    # Save analysis to DB
    try:
        threat_analysis = ThreatAnalysis(
            alert_id=alert_id,
            threat_type=analysis.get("threat_classification", {}).get("threat_type", "Unknown"),
            confidence=analysis.get("threat_classification", {}).get("confidence", "Low"),
            explanation=analysis.get("threat_classification", {}).get("explanation", ""),
            indicators=analysis.get("behavioral_analysis", {}).get("indicators", []),
            recommended_action=json.dumps(analysis.get("response_recommendation", {})),
            report=json.dumps(analysis.get("incident_report", {})),
            mitre_techniques=[t["technique_id"] for t in analysis.get("mitre_techniques", [])],
            severity_score=analysis.get("overall_severity_score", 0),
            campaign_id=analysis.get("correlation", {}).get("campaign", {}).get("campaign_id") if analysis.get("correlation", {}).get("campaign") else None,
            created_at=datetime.now()
        )
        db.add(threat_analysis)
        db.commit()
        logger.info(f"AI analysis saved for alert {alert_id}")
    except Exception as e:
        logger.error(f"Failed to save AI analysis: {e}")

    return analysis


@app.get("/api/report/{alert_id}")
def get_report(alert_id: int, db: Session = Depends(get_db)):
    """Get complete report for an alert including AI analysis."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    responses = db.query(Response).filter(Response.alert_id == alert_id).all()
    analyses = db.query(ThreatAnalysis).filter(ThreatAnalysis.alert_id == alert_id).order_by(ThreatAnalysis.created_at.desc()).all()

    return {
        "alert": alert,
        "responses": responses,
        "analyses": analyses,
        "summary": {
            "classification": alert.classification,
            "confidence": alert.final_score,
            "rf_score": alert.rf_score,
            "qsvm_score": alert.qsvm_score,
            "mode": alert.mode,
            "actions_taken": [r.action_type for r in responses],
            "ai_analyses_count": len(analyses)
        }
    }


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics."""
    total = db.query(Alert).count()
    malicious = db.query(Alert).filter(Alert.classification == "MALICIOUS").count()
    suspicious = db.query(Alert).filter(Alert.classification == "SUSPICIOUS").count()
    safe = db.query(Alert).filter(Alert.classification == "SAFE").count()
    potential_zero_day = db.query(Alert).filter(Alert.classification == "POTENTIAL_ZERO_DAY").count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    resolved = db.query(Alert).filter(Alert.status == "resolved").count()

    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "safe": safe,
        "potential_zero_day": potential_zero_day,
        "open_alerts": open_alerts,
        "resolved": resolved,
        "threat_rate": round(malicious / max(total, 1) * 100, 1),
        "detection_mode": "hybrid" if engine.qsvm_available else ("classical" if engine.rf_available else "rule_based")
    }


# ── WebSocket ──────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time alert streaming via WebSocket."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages (ping/pong, etc.)
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Helpers ────────────────────────────────────────────────
def _rule_based_score(event: dict) -> dict:
    """Fallback rule-based scoring when ML models are unavailable."""
    score = 0.0
    if event.get("network_connections", 0) > 20:
        score += 0.3
    if event.get("file_writes", 0) > 50:
        score += 0.3
    if event.get("suspicious_ports", 0) > 0:
        score += 0.2
    if event.get("registry_changes", 0) > 10:
        score += 0.1
    if event.get("child_processes", 0) > 3:
        score += 0.1
    score = min(score, 1.0)

    if score > 0.80:
        classification = "MALICIOUS"
    elif score > 0.50:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return {
        "classification": classification,
        "final_score": round(score, 4),
        "rf_score": round(score, 4),
        "qsvm_score": None,
        "anomaly_score": None,
        "is_potential_zero_day": False,
        "mode": "rule_based"
    }


def _determine_response(classification: str) -> str:
    """Determine automatic response action based on classification."""
    if classification == "MALICIOUS":
        return "kill_process + quarantine + network_isolation"
    elif classification == "SUSPICIOUS":
        return "quarantine + admin_alert"
    elif classification == "POTENTIAL_ZERO_DAY":
        return "quarantine + deep_analysis_triggered"
    else:
        return "log_only"


def _trigger_gemini_analysis(alert_id: int) -> None:
    """Fire-and-forget Gemini deep analysis for POTENTIAL_ZERO_DAY events (ADR Decision 3).

    Opens its own DB session so it is not tied to the request lifecycle.
    """
    db = next(get_db())
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return
        recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
        recent_dicts = [
            {
                "id": a.id, "process_name": a.process_name, "pid": a.pid,
                "parent_process": a.parent_process, "classification": a.classification,
                "final_score": a.final_score, "timestamp": a.timestamp,
                "network_connections": a.network_connections, "file_writes": a.file_writes,
                "registry_changes": a.registry_changes, "child_processes": a.child_processes,
                "unique_ips": a.unique_ips, "suspicious_ports": a.suspicious_ports,
            }
            for a in recent_alerts
        ]
        alert_dict = {
            "id": alert.id, "process_name": alert.process_name, "pid": alert.pid,
            "parent_process": alert.parent_process, "classification": alert.classification,
            "final_score": alert.final_score, "mode": alert.mode,
            "network_connections": alert.network_connections, "file_writes": alert.file_writes,
            "registry_changes": alert.registry_changes, "child_processes": alert.child_processes,
            "unique_ips": alert.unique_ips, "suspicious_ports": alert.suspicious_ports,
            "is_potential_zero_day": True,
        }
        analysis = analyze_threat(alert_dict, recent_dicts)
        threat_analysis = ThreatAnalysis(
            alert_id=alert_id,
            threat_type=analysis.get("threat_classification", {}).get("threat_type", "Unknown"),
            confidence=analysis.get("threat_classification", {}).get("confidence", "Low"),
            explanation=analysis.get("threat_classification", {}).get("explanation", ""),
            indicators=analysis.get("behavioral_analysis", {}).get("indicators", []),
            recommended_action=json.dumps(analysis.get("response_recommendation", {})),
            report=json.dumps(analysis.get("incident_report", {})),
            mitre_techniques=[t["technique_id"] for t in analysis.get("mitre_techniques", [])],
            severity_score=analysis.get("overall_severity_score", 0),
            campaign_id=analysis.get("correlation", {}).get("campaign", {}).get("campaign_id")
                        if analysis.get("correlation", {}).get("campaign") else None,
            created_at=datetime.now(),
        )
        db.add(threat_analysis)
        db.commit()
        logger.info(f"Auto Gemini analysis completed for POTENTIAL_ZERO_DAY alert {alert_id}")
    except Exception as e:
        logger.error(f"Auto Gemini analysis failed for alert {alert_id}: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)