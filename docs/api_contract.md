# API Contract — POST /api/event

**Version:** 2.0  
**Recipient:** Karim (Sysmon + ELK Stack)  
**Purpose:** Format specification for sending processed events from the Logstash pipeline to the Quantum EDR ML backend.

---

## Endpoint

```
POST http://<edr-host>:8000/api/event
Content-Type: application/json
X-API-Key: <key>          ← required in production, optional in dev
```

---

## Request Body

All fields are required unless marked optional.

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `process_name` | string | yes | Name of the process (from Sysmon Event 1 `Image`, filename only) | `"powershell.exe"` |
| `pid` | integer | yes | Process ID | `4821` |
| `parent_process` | string | yes | Parent process name (from `ParentImage`, filename only) | `"cmd.exe"` |
| `network_connections` | integer | no (default 0) | Total outbound connections in the 60s window | `87` |
| `file_writes` | integer | no (default 0) | Total file write operations in the 60s window | `14` |
| `registry_changes` | integer | no (default 0) | Total registry write/delete operations in the 60s window | `5` |
| `child_processes` | integer | no (default 0) | Number of child processes spawned in the 60s window | `3` |
| `unique_ips` | integer | no (default 0) | Number of distinct destination IPs contacted | `12` |
| `suspicious_ports` | integer | no (default 0) | Connections to suspicious ports (4444, 1337, 9999, 6666, 31337) | `1` |

---

## Example Request

```json
{
  "process_name": "powershell.exe",
  "pid": 4821,
  "parent_process": "cmd.exe",
  "network_connections": 87,
  "file_writes": 14,
  "registry_changes": 5,
  "child_processes": 3,
  "unique_ips": 12,
  "suspicious_ports": 1
}
```

Minimal request (only required fields — all numeric fields default to 0):

```json
{
  "process_name": "svchost.exe",
  "pid": 1092,
  "parent_process": "services.exe"
}
```

---

## Response Body

HTTP 200 on success.

```json
{
  "alert_id": 42,
  "process": "powershell.exe",
  "result": {
    "classification": "MALICIOUS",
    "final_score": 0.9341,
    "rf_score": 0.9512,
    "qsvm_score": 0.8874,
    "anomaly_score": -0.312451,
    "is_potential_zero_day": false,
    "mode": "hybrid"
  },
  "action": "kill_process + quarantine + network_isolation",
  "behavioral_indicators": ["high_network_activity", "suspicious_port_usage"],
  "behavioral_risk": 0.78
}
```

### `classification` values

| Value | Meaning |
|---|---|
| `MALICIOUS` | Supervised ensemble score > 0.80 — confirmed threat |
| `SUSPICIOUS` | Supervised ensemble score > 0.50 — investigate |
| `POTENTIAL_ZERO_DAY` | Supervised said SAFE but anomaly detector flagged it — novel/unknown threat, Gemini deep analysis triggered automatically |
| `SAFE` | No threat detected |

### `mode` values

| Value | Meaning |
|---|---|
| `hybrid` | RF + QSVM both active, dynamic weighting applied |
| `classical_only` | QSVM unavailable, RF only |
| `classical_fallback` | QSVM failed at runtime, RF result used |
| `rule_based` | ML models unavailable, heuristic scoring used |

### `anomaly_score`

Raw Isolation Forest score. **Negative = more anomalous, positive = normal.** `null` when the anomaly layer is not loaded. The internal threshold θ is calibrated so FPR ≤ 5% on benign traffic.

---

## Error Responses

| Code | Cause |
|---|---|
| 403 | Missing or invalid `X-API-Key` (production mode only) |
| 422 | Malformed request body — missing required field or wrong type |
| 500 | Internal server error — check backend logs |

---

## Notes for the Logstash Pipeline

1. **Aggregation window:** All count fields (`network_connections`, `file_writes`, etc.) must be aggregated over the **last 60 seconds per PID** before sending. One POST per process per window. Do not send raw per-event records.

2. **Process name format:** Send filename only — `powershell.exe`, not the full path `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Strip the path in Logstash using `grok` or `mutate`.

3. **Timing:** Send the event as soon as the 60s aggregation window closes, or immediately on process termination (Sysmon Event 5), whichever comes first.

4. **Feature mapping:** The 9 fields above are the current API interface. They map to a subset of the 28 features defined in `feature_requirements_v1.md`. The full 28-feature set is the target for a future API version — for now, send what you have.
