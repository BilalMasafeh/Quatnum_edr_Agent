"""
Quantum EDR AI Agent — Multi-Stage Threat Analysis Engine.

Combines rule-based threat intelligence with Gemini AI for comprehensive
threat analysis including:
  1. Behavioral Analysis (rule-based)
  2. Threat Classification (AI)
  3. MITRE ATT&CK Mapping
  4. Risk Assessment
  5. Incident Response Recommendations
  6. Report Generation
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import google.generativeai as genai
from dotenv import load_dotenv

from ai.threat_intel import analyze_behavior, check_known_process, check_parent_child, MITRE_TECHNIQUES
from ai.correlator import correlate

logger = logging.getLogger(__name__)

load_dotenv(Path(__file__).parent.parent / ".env")

# Configure Gemini
_api_key = os.getenv("GEMINI_API_KEY")
_model = None


def _get_model():
    """Lazy-initialize Gemini model."""
    global _model
    if _model is None:
        if not _api_key:
            logger.error("GEMINI_API_KEY not set — AI analysis disabled")
            return None
        genai.configure(api_key=_api_key)
        _model = genai.GenerativeModel("gemini-2.5-flash")
        logger.info("Gemini AI model initialized")
    return _model


def _call_gemini(prompt: str, max_retries: int = 3) -> Optional[str]:
    """Call Gemini with retry logic and exponential backoff."""
    model = _get_model()
    if model is None:
        return None

    for attempt in range(max_retries):
        try:
            response = model.generate_content(prompt)
            text = response.text.strip()
            # Clean markdown fences if present
            text = text.replace("```json", "").replace("```", "").strip()
            return text
        except Exception as e:
            wait_time = 2 ** attempt
            logger.warning(f"Gemini call failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(wait_time)
    
    logger.error("All Gemini retry attempts exhausted")
    return None


def _parse_json_response(text: str) -> Optional[dict]:
    """Safely parse JSON from Gemini response."""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON from text
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        logger.error(f"Failed to parse Gemini JSON response: {text[:200]}")
        return None


# ── Stage 1: Behavioral Analysis (Rule-Based) ─────────────
def stage_behavioral_analysis(alert: dict) -> dict:
    """
    Fast rule-based behavioral analysis.
    No AI needed — runs locally with threat intelligence rules.
    """
    behavior = analyze_behavior(alert)
    process_check = check_known_process(alert.get("process_name", ""))
    chain_check = check_parent_child(
        alert.get("parent_process", ""),
        alert.get("process_name", "")
    )

    return {
        "stage": "behavioral_analysis",
        "risk_score": behavior["risk_score"],
        "indicators": behavior["indicators"],
        "mitre_techniques": behavior["mitre_techniques"],
        "known_malicious": process_check,
        "suspicious_chain": chain_check,
        "indicator_count": behavior["indicator_count"]
    }


# ── Stage 2: AI Threat Classification ─────────────────────
def stage_threat_classification(alert: dict, behavioral: dict) -> dict:
    """
    Use Gemini AI for deep threat classification.
    Enriched with behavioral analysis context.
    """
    indicators_text = "\n".join(f"  - {i}" for i in behavioral.get("indicators", [])) or "  None detected"
    techniques_text = "\n".join(
        f"  - {t['technique_id']}: {t['name']} ({t['tactic']})"
        for t in behavioral.get("mitre_techniques", [])
    ) or "  None mapped"

    prompt = f"""You are an elite cybersecurity threat analyst at a SOC (Security Operations Center).
Analyze this endpoint security alert with the following data:

═══ ALERT DATA ═══
Process: {alert.get('process_name')}
PID: {alert.get('pid')}
Parent Process: {alert.get('parent_process')}
ML Classification: {alert.get('classification')}
ML Risk Score: {alert.get('final_score')}
Detection Mode: {alert.get('mode', 'N/A')}

═══ TELEMETRY ═══
Network Connections: {alert.get('network_connections', 0)}
File Writes: {alert.get('file_writes', 0)}
Registry Changes: {alert.get('registry_changes', 0)}
Child Processes: {alert.get('child_processes', 0)}
Unique IPs Contacted: {alert.get('unique_ips', 0)}
Suspicious Port Connections: {alert.get('suspicious_ports', 0)}

═══ BEHAVIORAL ANALYSIS (Pre-computed) ═══
Behavioral Risk Score: {behavioral.get('risk_score', 0)}
Indicators Found:
{indicators_text}

MITRE ATT&CK Techniques:
{techniques_text}

═══ INSTRUCTIONS ═══
Provide a detailed threat classification. Consider ALL the telemetry data and behavioral indicators.
Think about what type of malware or attack this behavior pattern matches.

Respond in this exact JSON format:
{{
    "threat_type": "Ransomware|Trojan|Spyware|Botnet|Worm|Rootkit|Cryptominer|RAT|APT|Adware|PUP|Legitimate|Unknown",
    "threat_family": "Specific malware family name or 'N/A'",
    "confidence": "Critical|High|Medium|Low",
    "kill_chain_phase": "Reconnaissance|Weaponization|Delivery|Exploitation|Installation|Command_Control|Actions_on_Objectives",
    "explanation": "3-4 sentences explaining the threat classification with technical detail",
    "attack_vector": "How the attack likely entered the system",
    "data_at_risk": "What data or systems are at risk"
}}

Return ONLY the JSON object."""

    text = _call_gemini(prompt)
    result = _parse_json_response(text)

    if result:
        return {"stage": "threat_classification", **result}
    
    return {
        "stage": "threat_classification",
        "threat_type": "Unknown",
        "threat_family": "N/A",
        "confidence": "Low",
        "kill_chain_phase": "Unknown",
        "explanation": "AI classification unavailable — manual analysis recommended",
        "attack_vector": "Unknown",
        "data_at_risk": "Assessment pending"
    }


# ── Stage 3: Response Recommendation ──────────────────────
def stage_response_recommendation(alert: dict, classification: dict, behavioral: dict) -> dict:
    """
    Generate specific incident response recommendations using AI.
    """
    prompt = f"""You are a senior incident responder. Based on the following threat analysis,
provide specific, actionable response recommendations.

═══ THREAT SUMMARY ═══
Process: {alert.get('process_name')} (PID: {alert.get('pid')})
Threat Type: {classification.get('threat_type', 'Unknown')}
Threat Family: {classification.get('threat_family', 'N/A')}
Confidence: {classification.get('confidence', 'Unknown')}
Kill Chain Phase: {classification.get('kill_chain_phase', 'Unknown')}
Risk Score: {alert.get('final_score', 0)}
Behavioral Risk: {behavioral.get('risk_score', 0)}

═══ INSTRUCTIONS ═══
Provide prioritized response actions. Be SPECIFIC — include exact commands,
tools, and procedures where applicable.

Respond in this exact JSON format:
{{
    "severity_level": "P1_CRITICAL|P2_HIGH|P3_MEDIUM|P4_LOW",
    "immediate_actions": ["Action 1 with specific details", "Action 2", "Action 3"],
    "containment_steps": ["Step 1", "Step 2"],
    "eradication_steps": ["Step 1", "Step 2"],
    "recovery_steps": ["Step 1", "Step 2"],
    "monitoring_recommendations": ["What to monitor going forward"],
    "escalation_required": true/false,
    "escalation_reason": "Why escalation is needed or 'N/A'"
}}

Return ONLY the JSON object."""

    text = _call_gemini(prompt)
    result = _parse_json_response(text)

    if result:
        return {"stage": "response_recommendation", **result}

    # Default response based on classification
    classification_level = alert.get("classification", "SAFE")
    return {
        "stage": "response_recommendation",
        "severity_level": "P2_HIGH" if classification_level == "MALICIOUS" else "P3_MEDIUM",
        "immediate_actions": [
            "Isolate the endpoint from the network",
            "Kill the suspicious process",
            "Collect forensic artifacts"
        ],
        "containment_steps": ["Network isolation", "Process termination"],
        "eradication_steps": ["Full system scan", "Remove malicious artifacts"],
        "recovery_steps": ["Restore from clean backup", "Monitor for recurrence"],
        "monitoring_recommendations": ["Monitor for similar process names", "Watch for C2 callbacks"],
        "escalation_required": classification_level == "MALICIOUS",
        "escalation_reason": "AI response unavailable — manual review needed"
    }


# ── Stage 4: Report Generation ────────────────────────────
def stage_report_generation(alert: dict, classification: dict, behavioral: dict, response: dict) -> dict:
    """Generate a comprehensive incident report using AI."""
    indicators_text = ", ".join(behavioral.get("indicators", [])[:5]) or "None"
    actions_text = ", ".join(response.get("immediate_actions", [])[:3]) or "Standard response"

    prompt = f"""You are a cybersecurity report writer. Generate a professional incident report.

═══ INCIDENT DATA ═══
Process: {alert.get('process_name')} (PID: {alert.get('pid')})
Parent: {alert.get('parent_process')}
Threat Type: {classification.get('threat_type', 'Unknown')}
Confidence: {classification.get('confidence', 'Unknown')}
Severity: {response.get('severity_level', 'Unknown')}
Key Indicators: {indicators_text}
Recommended Actions: {actions_text}

═══ INSTRUCTIONS ═══
Write a concise but comprehensive incident report.

Respond in this exact JSON format:
{{
    "title": "Short incident title",
    "executive_summary": "2-3 sentence summary for management",
    "technical_details": "4-5 sentence technical analysis",
    "impact_assessment": "What is the potential business impact",
    "timeline": "Brief timeline of events",
    "recommendations": "Key recommendations summary"
}}

Return ONLY the JSON object."""

    text = _call_gemini(prompt)
    result = _parse_json_response(text)

    if result:
        return {"stage": "report_generation", **result}

    return {
        "stage": "report_generation",
        "title": f"Security Incident: {alert.get('process_name', 'Unknown Process')}",
        "executive_summary": f"A {classification.get('threat_type', 'suspicious')} threat was detected on endpoint.",
        "technical_details": f"Process {alert.get('process_name')} (PID {alert.get('pid')}) was flagged with a risk score of {alert.get('final_score', 0)}.",
        "impact_assessment": "Full impact assessment requires manual investigation.",
        "timeline": f"Alert generated at detection time.",
        "recommendations": "Isolate endpoint and conduct forensic investigation."
    }


# ── Full Multi-Stage Analysis ──────────────────────────────
def analyze_threat(alert: dict, recent_alerts: list | None = None) -> dict:
    """
    Run the full multi-stage AI threat analysis pipeline.
    
    Stages:
        1. Behavioral Analysis (rule-based, instant)
        2. Threat Classification (AI)
        3. Alert Correlation (rule-based)
        4. Response Recommendation (AI)
        5. Report Generation (AI)
    
    Args:
        alert: Alert dict with event data
        recent_alerts: Optional list of recent alerts for correlation
        
    Returns:
        Complete analysis result with all stages
    """
    recent_alerts = recent_alerts or []
    start_time = time.time()

    logger.info(f"Starting multi-stage analysis for alert: {alert.get('process_name')} (PID: {alert.get('pid')})")

    # Stage 1: Behavioral Analysis (always runs, no AI needed)
    behavioral = stage_behavioral_analysis(alert)
    logger.info(f"  Stage 1 complete: {behavioral['indicator_count']} indicators, risk={behavioral['risk_score']}")

    # Stage 2: AI Threat Classification
    classification = stage_threat_classification(alert, behavioral)
    logger.info(f"  Stage 2 complete: {classification.get('threat_type')}, confidence={classification.get('confidence')}")

    # Stage 3: Alert Correlation
    correlation = correlate(recent_alerts, alert)
    logger.info(f"  Stage 3 complete: {correlation['related_count']} related alerts, campaign={correlation['is_part_of_campaign']}")

    # Stage 4: Response Recommendation
    response = stage_response_recommendation(alert, classification, behavioral)
    logger.info(f"  Stage 4 complete: severity={response.get('severity_level')}")

    # Stage 5: Report Generation
    report = stage_report_generation(alert, classification, behavioral, response)
    logger.info(f"  Stage 5 complete: {report.get('title')}")

    elapsed = round(time.time() - start_time, 2)
    logger.info(f"Multi-stage analysis complete in {elapsed}s")

    # Compute overall severity
    severity_score = _compute_severity(alert, behavioral, classification)

    return {
        "alert_id": alert.get("id"),
        "process_name": alert.get("process_name"),
        "analysis_time_seconds": elapsed,
        "overall_severity_score": severity_score,
        "behavioral_analysis": behavioral,
        "threat_classification": classification,
        "correlation": correlation,
        "response_recommendation": response,
        "incident_report": report,
        "mitre_techniques": behavioral.get("mitre_techniques", [])
    }


def quick_analyze(alert: dict) -> dict:
    """
    Run a fast analysis (behavioral only, no AI calls).
    Useful for real-time scoring.
    """
    behavioral = stage_behavioral_analysis(alert)
    return {
        "alert_id": alert.get("id"),
        "process_name": alert.get("process_name"),
        "risk_score": behavioral["risk_score"],
        "indicators": behavioral["indicators"],
        "mitre_techniques": behavioral["mitre_techniques"],
        "known_malicious": behavioral["known_malicious"],
        "mode": "quick_analysis"
    }


def _compute_severity(alert: dict, behavioral: dict, classification: dict) -> float:
    """Compute an overall severity score from 0-10."""
    score = 0.0

    # ML score contribution (0-3 points)
    ml_score = alert.get("final_score", 0)
    score += ml_score * 3.0

    # Behavioral risk contribution (0-3 points)
    score += behavioral.get("risk_score", 0) * 3.0

    # AI classification contribution (0-4 points)
    confidence_map = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0}
    score += confidence_map.get(classification.get("confidence", "Low"), 0)

    return round(min(score, 10.0), 1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
    
    test_alert = {
        "process_name": "malware.exe",
        "pid": 1234,
        "parent_process": "cmd.exe",
        "classification": "MALICIOUS",
        "final_score": 1.0,
        "network_connections": 50,
        "file_writes": 100,
        "registry_changes": 20,
        "child_processes": 5,
        "suspicious_ports": 3,
        "unique_ips": 25
    }
    
    # Quick analysis (no AI)
    quick = quick_analyze(test_alert)
    print("\n=== Quick Analysis ===")
    print(json.dumps(quick, indent=2))
    
    # Full analysis (with AI)
    result = analyze_threat(test_alert)
    print("\n=== Full Analysis ===")
    print(json.dumps(result, indent=2, default=str))