import logging
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now())
    process_name = Column(String(255))
    pid = Column(Integer)
    parent_process = Column(String(255))
    classification = Column(String(50))  # MALICIOUS, SUSPICIOUS, SAFE, POTENTIAL_ZERO_DAY
    final_score = Column(Float)
    rf_score = Column(Float)
    qsvm_score = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    is_potential_zero_day = Column(Boolean, default=False)
    mode = Column(String(50))  # hybrid, classical_only, classical_fallback, rule_based
    status = Column(String(50), default="open")  # open, resolved, dismissed, escalated

    # Event data stored for AI re-analysis
    network_connections = Column(Integer, default=0)
    file_writes = Column(Integer, default=0)
    registry_changes = Column(Integer, default=0)
    child_processes = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    suspicious_ports = Column(Integer, default=0)

    # Relationships
    responses = relationship("Response", back_populates="alert", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="alert", cascade="all, delete-orphan")
    analyses = relationship("ThreatAnalysis", back_populates="alert", cascade="all, delete-orphan")


class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    action_type = Column(String(100))  # kill_process, quarantine, network_isolation, admin_alert, log_only
    timestamp = Column(DateTime, default=func.now())
    success = Column(Boolean, default=True)
    details = Column(Text)

    # Relationships
    alert = relationship("Alert", back_populates="responses")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    malware_family = Column(String(255))
    confidence = Column(Float)
    timeline = Column(Text)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    alert = relationship("Alert", back_populates="reports")


class ThreatAnalysis(Base):
    """Stores AI-generated threat analysis results."""
    __tablename__ = "threat_analyses"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    threat_type = Column(String(100))  # Ransomware, Trojan, Spyware, Botnet, etc.
    confidence = Column(String(20))  # High, Medium, Low
    explanation = Column(Text)
    indicators = Column(JSON, default=list)
    recommended_action = Column(Text)
    report = Column(Text)
    mitre_techniques = Column(JSON, default=list)  # ATT&CK technique IDs
    severity_score = Column(Float, default=0.0)
    campaign_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    alert = relationship("Alert", back_populates="analyses")