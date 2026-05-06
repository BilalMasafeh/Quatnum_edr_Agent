"""
Threat Intelligence Module for Quantum EDR.
Contains known malicious signatures, behavioral patterns,
IOC matching rules, and process relationship analysis.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Known Malicious Process Signatures ─────────────────────
KNOWN_MALICIOUS_PROCESSES = {
    "mimikatz.exe": {"family": "Credential Dumper", "severity": 10, "technique": "T1003"},
    "lazagne.exe": {"family": "Credential Harvester", "severity": 9, "technique": "T1555"},
    "psexec.exe": {"family": "Lateral Movement Tool", "severity": 7, "technique": "T1570"},
    "cobalt_strike": {"family": "C2 Framework", "severity": 10, "technique": "T1071"},
    "netcat.exe": {"family": "Network Utility / Backdoor", "severity": 8, "technique": "T1095"},
    "nc.exe": {"family": "Network Utility / Backdoor", "severity": 8, "technique": "T1095"},
    "ncat.exe": {"family": "Network Utility / Backdoor", "severity": 8, "technique": "T1095"},
    "procdump.exe": {"family": "Memory Dumper", "severity": 7, "technique": "T1003.001"},
    "wce.exe": {"family": "Credential Editor", "severity": 9, "technique": "T1003"},
    "bloodhound": {"family": "AD Reconnaissance", "severity": 8, "technique": "T1087.002"},
    "sharphound": {"family": "AD Reconnaissance", "severity": 8, "technique": "T1087.002"},
    "rubeus.exe": {"family": "Kerberos Attack Tool", "severity": 9, "technique": "T1558"},
    "certutil.exe": {"family": "LOLBin", "severity": 5, "technique": "T1105"},
    "bitsadmin.exe": {"family": "LOLBin", "severity": 5, "technique": "T1197"},
    "mshta.exe": {"family": "LOLBin", "severity": 6, "technique": "T1218.005"},
    "regsvr32.exe": {"family": "LOLBin", "severity": 5, "technique": "T1218.010"},
    "rundll32.exe": {"family": "LOLBin", "severity": 4, "technique": "T1218.011"},
}

# ── Suspicious Parent-Child Relationships ──────────────────
SUSPICIOUS_CHAINS = [
    {"parent": "outlook.exe", "child_patterns": ["cmd.exe", "powershell.exe", "wscript.exe"],
     "description": "Email client spawning scripting engine", "technique": "T1566.001"},
    {"parent": "winword.exe", "child_patterns": ["cmd.exe", "powershell.exe", "wscript.exe"],
     "description": "Office document spawning scripting engine", "technique": "T1566.001"},
    {"parent": "excel.exe", "child_patterns": ["cmd.exe", "powershell.exe", "wscript.exe"],
     "description": "Office spreadsheet spawning scripting engine", "technique": "T1566.001"},
    {"parent": "iexplore.exe", "child_patterns": ["cmd.exe", "powershell.exe"],
     "description": "Browser spawning command shell", "technique": "T1189"},
    {"parent": "svchost.exe", "child_patterns": ["cmd.exe", "powershell.exe"],
     "description": "Service host spawning command shell", "technique": "T1543.003"},
    {"parent": "cmd.exe", "child_patterns": ["powershell.exe"],
     "description": "Command shell spawning PowerShell", "technique": "T1059.001"},
    {"parent": "services.exe", "child_patterns": ["cmd.exe", "powershell.exe"],
     "description": "Services controller spawning shell", "technique": "T1543.003"},
    {"parent": "wmiprvse.exe", "child_patterns": ["cmd.exe", "powershell.exe"],
     "description": "WMI provider spawning shell (possible lateral movement)", "technique": "T1047"},
]

# ── Suspicious Network Ports ──────────────────────────────
SUSPICIOUS_PORTS = {
    4444: {"name": "Metasploit default", "risk": 9},
    1337: {"name": "Common backdoor", "risk": 8},
    9999: {"name": "Common backdoor", "risk": 7},
    6666: {"name": "IRC / backdoor", "risk": 7},
    6667: {"name": "IRC C2", "risk": 7},
    8888: {"name": "Alternate HTTP / backdoor", "risk": 5},
    31337: {"name": "Back Orifice", "risk": 9},
    12345: {"name": "NetBus", "risk": 8},
    5555: {"name": "ADB / backdoor", "risk": 6},
    7777: {"name": "Common backdoor", "risk": 7},
    1234: {"name": "Common test/backdoor", "risk": 5},
    5900: {"name": "VNC (unauthorized remote access)", "risk": 6},
    3389: {"name": "RDP (if unexpected)", "risk": 5},
}

# ── MITRE ATT&CK Technique Database ───────────────────────
MITRE_TECHNIQUES = {
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1047": {"name": "WMI", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "Discovery"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1197": {"name": "BITS Jobs", "tactic": "Defense Evasion"},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
}


def check_known_process(process_name: str) -> Optional[dict]:
    """Check if a process name matches known malicious signatures."""
    name_lower = process_name.lower()
    for pattern, info in KNOWN_MALICIOUS_PROCESSES.items():
        if pattern in name_lower:
            return {
                "match": pattern,
                "family": info["family"],
                "severity": info["severity"],
                "technique": info["technique"],
                "technique_name": MITRE_TECHNIQUES.get(info["technique"], {}).get("name", "Unknown")
            }
    return None


def check_parent_child(parent_process: str, child_process: str) -> Optional[dict]:
    """Check if a parent-child process relationship is suspicious."""
    parent_lower = parent_process.lower()
    child_lower = child_process.lower()

    for chain in SUSPICIOUS_CHAINS:
        if chain["parent"] in parent_lower:
            for pattern in chain["child_patterns"]:
                if pattern in child_lower:
                    return {
                        "parent": parent_process,
                        "child": child_process,
                        "description": chain["description"],
                        "technique": chain["technique"],
                        "technique_name": MITRE_TECHNIQUES.get(chain["technique"], {}).get("name", "Unknown")
                    }
    return None


def analyze_behavior(event: dict) -> dict:
    """
    Perform rule-based behavioral analysis on an event.
    Returns a behavioral risk assessment with indicators.
    """
    indicators = []
    risk_score = 0.0
    techniques = []

    # Check known malicious process
    proc_match = check_known_process(event.get("process_name", ""))
    if proc_match:
        indicators.append(f"Known malicious tool: {proc_match['family']} ({proc_match['match']})")
        risk_score += proc_match["severity"] / 10.0
        techniques.append(proc_match["technique"])

    # Check parent-child chain
    chain_match = check_parent_child(
        event.get("parent_process", ""),
        event.get("process_name", "")
    )
    if chain_match:
        indicators.append(f"Suspicious process chain: {chain_match['description']}")
        risk_score += 0.3
        techniques.append(chain_match["technique"])

    # Network behavior analysis
    net_conns = event.get("network_connections", 0)
    if net_conns > 50:
        indicators.append(f"Excessive network connections ({net_conns}) — possible C2 beaconing or data exfiltration")
        risk_score += 0.3
        techniques.append("T1071")
    elif net_conns > 20:
        indicators.append(f"High network activity ({net_conns} connections)")
        risk_score += 0.15

    # File system behavior
    file_writes = event.get("file_writes", 0)
    if file_writes > 100:
        indicators.append(f"Mass file writes ({file_writes}) — possible ransomware encryption")
        risk_score += 0.4
        techniques.append("T1486")
    elif file_writes > 50:
        indicators.append(f"High file write activity ({file_writes})")
        risk_score += 0.2

    # Registry modifications
    reg_changes = event.get("registry_changes", 0)
    if reg_changes > 10:
        indicators.append(f"Significant registry modifications ({reg_changes}) — possible persistence mechanism")
        risk_score += 0.2
        techniques.append("T1547.001")
    elif reg_changes > 5:
        indicators.append(f"Registry changes detected ({reg_changes})")
        risk_score += 0.1

    # Child process spawning
    child_procs = event.get("child_processes", 0)
    if child_procs > 5:
        indicators.append(f"Multiple child processes spawned ({child_procs}) — possible process injection or lateral movement")
        risk_score += 0.2
        techniques.append("T1055")
    elif child_procs > 3:
        indicators.append(f"Notable child process activity ({child_procs})")
        risk_score += 0.1

    # Suspicious port usage
    susp_ports = event.get("suspicious_ports", 0)
    if susp_ports > 0:
        indicators.append(f"Communication on suspicious ports ({susp_ports} connections)")
        risk_score += 0.3 * min(susp_ports, 3)
        techniques.append("T1095")

    # Unique IP analysis
    unique_ips = event.get("unique_ips", 0)
    if unique_ips > 20:
        indicators.append(f"Connections to many unique IPs ({unique_ips}) — possible scanning or C2 rotation")
        risk_score += 0.2
        techniques.append("T1046")

    risk_score = min(risk_score, 1.0)

    # Deduplicate techniques and get names
    unique_techniques = list(set(techniques))
    mitre_mapping = []
    for tid in unique_techniques:
        info = MITRE_TECHNIQUES.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        mitre_mapping.append({
            "technique_id": tid,
            "name": info["name"],
            "tactic": info["tactic"]
        })

    return {
        "risk_score": round(risk_score, 4),
        "indicators": indicators,
        "mitre_techniques": mitre_mapping,
        "indicator_count": len(indicators)
    }


def get_technique_info(technique_id: str) -> Optional[dict]:
    """Look up MITRE ATT&CK technique details."""
    return MITRE_TECHNIQUES.get(technique_id)
