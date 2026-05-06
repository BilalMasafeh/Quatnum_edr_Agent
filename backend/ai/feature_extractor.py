import numpy as np
import logging

logger = logging.getLogger(__name__)


# ── Real Elasticsearch extraction ──────────────────────────
def extract_from_elasticsearch(process_id, time_window=60):
    """Extract features from Elasticsearch/Sysmon logs for a given process."""
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch('http://localhost:9200')

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"winlog.event_data.ProcessId": process_id}},
                        {"range": {"@timestamp": {"gte": f"now-{time_window}s"}}}
                    ]
                }
            },
            "size": 1000
        }

        res = es.search(index='sysmon-*', body=query)
        hits = res['hits']['hits']

        network_connections = sum(1 for h in hits
            if h['_source'].get('event.code') == '3')
        file_writes = sum(1 for h in hits
            if h['_source'].get('event.code') == '11')
        registry_changes = sum(1 for h in hits
            if h['_source'].get('event.code') in ['12', '13'])
        child_processes = sum(1 for h in hits
            if h['_source'].get('event.code') == '1')
        unique_ips = len(set(h['_source'].get('destination.ip', '')
            for h in hits if h['_source'].get('event.code') == '3'))
        suspicious_ports = sum(1 for h in hits
            if h['_source'].get('destination.port') in [4444, 1337, 9999, 6666])

        return np.array([
            network_connections,
            file_writes,
            registry_changes,
            child_processes,
            unique_ips,
            suspicious_ports
        ], dtype=float)

    except ImportError:
        logger.warning("Elasticsearch package not installed")
        return None
    except ConnectionError:
        logger.warning("Elasticsearch not reachable")
        return None
    except Exception as e:
        logger.error(f"Elasticsearch extraction failed: {e}")
        return None


# ── Mock data for testing ──────────────────────────────────
def generate_mock_event(threat_level="normal"):
    """Generate mock event data for testing when Elasticsearch is unavailable."""
    if threat_level == "malicious":
        return {
            "process_name": "malware.exe",
            "pid": 1234,
            "parent_process": "cmd.exe",
            "network_connections": 50,
            "file_writes": 100,
            "registry_changes": 20,
            "child_processes": 5,
            "unique_ips": 30,
            "suspicious_ports": 3
        }
    elif threat_level == "suspicious":
        return {
            "process_name": "unknown.exe",
            "pid": 5678,
            "parent_process": "explorer.exe",
            "network_connections": 15,
            "file_writes": 25,
            "registry_changes": 5,
            "child_processes": 2,
            "unique_ips": 8,
            "suspicious_ports": 1
        }
    else:
        return {
            "process_name": "chrome.exe",
            "pid": 9012,
            "parent_process": "explorer.exe",
            "network_connections": 5,
            "file_writes": 2,
            "registry_changes": 0,
            "child_processes": 1,
            "unique_ips": 3,
            "suspicious_ports": 0
        }


def event_to_features(event: dict) -> np.ndarray:
    """
    Convert a raw event dict into an unscaled feature vector for ML models.
    Maps endpoint event counters to the 6 CICIDS2017-like features.

    Scaling is intentionally left to the ensemble/model layer so it happens
    exactly once — ensemble.py applies scaler.pkl before feeding the RF model,
    and q_scaler.pkl before feeding the QSVM.
    """
    return np.array([
        event.get("network_connections", 0) * 1000,   # Approx flow duration (ms)
        event.get("network_connections", 0),            # Forward packet count proxy
        event.get("file_writes", 0),                    # Backward packet count proxy
        event.get("file_writes", 0) * 500,              # Flow bytes/s approximation
        event.get("unique_ips", 0) * 100,               # Fwd IAT mean approximation
        event.get("suspicious_ports", 0) * 1000         # Destination port risk score
    ], dtype=float)


def extract_features(process_id=None, use_mock=False, threat_level="normal"):
    """
    Extract features for a process.
    Queries Elasticsearch by default; raises RuntimeError if unavailable.
    Pass use_mock=True explicitly for demo/testing without Elasticsearch.
    """
    if use_mock:
        event = generate_mock_event(threat_level)
        return event_to_features(event)

    if not process_id:
        raise ValueError("process_id is required when use_mock=False")

    features = extract_from_elasticsearch(process_id)
    if features is None:
        raise RuntimeError(
            "Elasticsearch is unavailable or returned no data for process "
            f"{process_id}. Ensure Elasticsearch is running at localhost:9200 "
            "and Sysmon logs are being indexed under 'sysmon-*'."
        )
    return features


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== Testing Feature Extractor ===")
    for level in ["normal", "suspicious", "malicious"]:
        features = extract_features(threat_level=level)
        print(f"\n{level}: {features}")