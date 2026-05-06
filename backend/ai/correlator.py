"""
Alert Correlation Engine for Quantum EDR.
Detects attack campaigns, correlates alerts across time windows,
and identifies multi-stage attack patterns.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class AlertCorrelator:
    """
    Cross-alert correlation engine.
    Groups related alerts into campaigns and detects attack patterns.
    """

    # Time window for correlation (seconds)
    CORRELATION_WINDOW = 300  # 5 minutes
    
    # Minimum alerts to form a campaign
    MIN_CAMPAIGN_ALERTS = 2

    # Attack chain patterns (ordered stages)
    ATTACK_CHAINS = [
        {
            "name": "Phishing → Execution → C2",
            "stages": ["INITIAL_ACCESS", "EXECUTION", "COMMAND_AND_CONTROL"],
            "description": "Classic phishing attack leading to malware execution and C2 communication"
        },
        {
            "name": "Reconnaissance → Lateral Movement → Exfiltration",
            "stages": ["DISCOVERY", "LATERAL_MOVEMENT", "EXFILTRATION"],
            "description": "Active intrusion with internal scanning and data theft"
        },
        {
            "name": "Credential Theft → Privilege Escalation",
            "stages": ["CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION"],
            "description": "Credential harvesting followed by privilege escalation"
        },
        {
            "name": "Persistence → Defense Evasion → Execution",
            "stages": ["PERSISTENCE", "DEFENSE_EVASION", "EXECUTION"],
            "description": "Establishing persistence while evading detection"
        },
    ]

    def __init__(self):
        self._campaigns = {}
        self._alert_campaign_map = {}

    def correlate_alerts(self, alerts: list, current_alert: dict) -> dict:
        """
        Correlate the current alert with recent alerts to detect campaigns.
        
        Args:
            alerts: List of recent alert dicts
            current_alert: The new alert being analyzed
            
        Returns:
            Correlation result with campaign info, related alerts, and patterns
        """
        related_alerts = []
        correlation_factors = []

        current_time = datetime.now()
        current_process = current_alert.get("process_name", "").lower()
        current_parent = current_alert.get("parent_process", "").lower()

        for alert in alerts:
            if alert.get("id") == current_alert.get("id"):
                continue

            alert_time = alert.get("timestamp")
            if isinstance(alert_time, str):
                try:
                    alert_time = datetime.fromisoformat(alert_time)
                except (ValueError, TypeError):
                    continue
            
            if alert_time is None:
                continue

            # Time proximity check
            time_diff = abs((current_time - alert_time).total_seconds())
            if time_diff > self.CORRELATION_WINDOW:
                continue

            similarity_score = 0.0
            reasons = []

            # Same process name
            alert_process = (alert.get("process_name") or "").lower()
            if alert_process == current_process:
                similarity_score += 0.3
                reasons.append("Same process name")

            # Same parent process
            alert_parent = (alert.get("parent_process") or "").lower()
            if alert_parent == current_parent:
                similarity_score += 0.2
                reasons.append("Same parent process")

            # Both classified as threats
            if (alert.get("classification") in ["MALICIOUS", "SUSPICIOUS"] and
                current_alert.get("classification") in ["MALICIOUS", "SUSPICIOUS"]):
                similarity_score += 0.2
                reasons.append("Both classified as threats")

            # Same classification
            if alert.get("classification") == current_alert.get("classification"):
                similarity_score += 0.1
                reasons.append("Same classification level")

            # Time proximity bonus
            if time_diff < 60:
                similarity_score += 0.2
                reasons.append(f"Very close in time ({int(time_diff)}s apart)")
            elif time_diff < 180:
                similarity_score += 0.1
                reasons.append(f"Close in time ({int(time_diff)}s apart)")

            if similarity_score >= 0.3:
                related_alerts.append({
                    "alert_id": alert.get("id"),
                    "process_name": alert.get("process_name"),
                    "classification": alert.get("classification"),
                    "similarity_score": round(similarity_score, 2),
                    "reasons": reasons,
                    "time_diff_seconds": int(time_diff)
                })

        # Sort by similarity
        related_alerts.sort(key=lambda x: x["similarity_score"], reverse=True)

        # Determine campaign
        campaign = None
        if len(related_alerts) >= self.MIN_CAMPAIGN_ALERTS:
            campaign = self._identify_campaign(current_alert, related_alerts)

        # Detect attack chain patterns
        attack_chain = self._detect_attack_chain(current_alert, related_alerts, alerts)

        return {
            "related_alerts": related_alerts[:10],  # Top 10 related
            "related_count": len(related_alerts),
            "campaign": campaign,
            "attack_chain": attack_chain,
            "is_part_of_campaign": campaign is not None,
            "correlation_window_seconds": self.CORRELATION_WINDOW
        }

    def _identify_campaign(self, current_alert: dict, related_alerts: list) -> Optional[dict]:
        """Identify if alerts form a campaign."""
        high_similarity = [a for a in related_alerts if a["similarity_score"] >= 0.5]
        
        if len(high_similarity) < self.MIN_CAMPAIGN_ALERTS:
            return None

        # Generate campaign ID from common attributes
        processes = set()
        processes.add(current_alert.get("process_name", "unknown"))
        for a in high_similarity:
            processes.add(a.get("process_name", "unknown"))

        campaign_id = f"CAMP-{hash(frozenset(processes)) % 100000:05d}"

        # Determine campaign type
        classifications = [a.get("classification", "") for a in high_similarity]
        if classifications.count("MALICIOUS") > len(classifications) // 2:
            campaign_type = "Active Attack"
            severity = "CRITICAL"
        elif classifications.count("SUSPICIOUS") > len(classifications) // 2:
            campaign_type = "Suspicious Activity Cluster"
            severity = "HIGH"
        else:
            campaign_type = "Anomalous Behavior Pattern"
            severity = "MEDIUM"

        return {
            "campaign_id": campaign_id,
            "campaign_type": campaign_type,
            "severity": severity,
            "involved_processes": list(processes),
            "alert_count": len(high_similarity) + 1,
            "description": f"{campaign_type} involving {len(processes)} processes with {len(high_similarity) + 1} correlated alerts"
        }

    def _detect_attack_chain(self, current_alert: dict, related_alerts: list, all_alerts: list) -> Optional[dict]:
        """Detect if alerts match a known attack chain pattern."""
        # Map alerts to tactic categories based on behavior
        alert_tactics = set()
        
        current_tactics = self._classify_tactics(current_alert)
        alert_tactics.update(current_tactics)

        for ra in related_alerts[:5]:
            # Find the full alert data
            for a in all_alerts:
                if a.get("id") == ra.get("alert_id"):
                    tactics = self._classify_tactics(a)
                    alert_tactics.update(tactics)
                    break

        # Check against known attack chains
        for chain in self.ATTACK_CHAINS:
            matched_stages = [s for s in chain["stages"] if s in alert_tactics]
            if len(matched_stages) >= 2:
                return {
                    "chain_name": chain["name"],
                    "description": chain["description"],
                    "matched_stages": matched_stages,
                    "total_stages": len(chain["stages"]),
                    "completion_pct": round(len(matched_stages) / len(chain["stages"]) * 100)
                }

        return None

    def _classify_tactics(self, alert: dict) -> list:
        """Classify an alert into MITRE ATT&CK tactic categories."""
        tactics = []
        process = (alert.get("process_name") or "").lower()
        parent = (alert.get("parent_process") or "").lower()

        # Execution indicators
        if any(p in process for p in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]):
            tactics.append("EXECUTION")

        # Initial access
        if any(p in parent for p in ["outlook.exe", "winword.exe", "excel.exe"]):
            tactics.append("INITIAL_ACCESS")

        # Credential access
        if any(p in process for p in ["mimikatz", "lazagne", "procdump", "wce.exe"]):
            tactics.append("CREDENTIAL_ACCESS")

        # C2 indicators
        net_conns = alert.get("network_connections", 0) or 0
        susp_ports = alert.get("suspicious_ports", 0) or 0
        if net_conns > 30 or susp_ports > 0:
            tactics.append("COMMAND_AND_CONTROL")

        # Lateral movement
        if any(p in process for p in ["psexec", "wmic.exe"]):
            tactics.append("LATERAL_MOVEMENT")

        # Discovery
        unique_ips = alert.get("unique_ips", 0) or 0
        if unique_ips > 15:
            tactics.append("DISCOVERY")

        # Persistence
        reg_changes = alert.get("registry_changes", 0) or 0
        if reg_changes > 5:
            tactics.append("PERSISTENCE")

        # Defense evasion
        if any(p in process for p in ["rundll32.exe", "regsvr32.exe", "mshta.exe"]):
            tactics.append("DEFENSE_EVASION")

        # Data exfiltration
        file_writes = alert.get("file_writes", 0) or 0
        if file_writes > 80 and net_conns > 20:
            tactics.append("EXFILTRATION")

        # Privilege escalation
        child_procs = alert.get("child_processes", 0) or 0
        if child_procs > 5 and reg_changes > 5:
            tactics.append("PRIVILEGE_ESCALATION")

        return tactics


# Module-level singleton
_correlator = AlertCorrelator()


def correlate(alerts: list, current_alert: dict) -> dict:
    """Convenience function using the singleton correlator."""
    return _correlator.correlate_alerts(alerts, current_alert)
