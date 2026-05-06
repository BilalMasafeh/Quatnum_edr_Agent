export const SEVERITY_COLORS = {
  MALICIOUS: 'var(--danger)',
  SUSPICIOUS: 'var(--warning)',
  SAFE: 'var(--success)',
  UNKNOWN: 'var(--text-muted)'
};

export const STATUS_COLORS = {
  open: 'var(--danger)',
  resolved: 'var(--success)',
  dismissed: 'var(--text-muted)',
  escalated: 'var(--warning)'
};

export const MITRE_TACTICS = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0011: 'Command and Control',
  TA0010: 'Exfiltration',
  TA0040: 'Impact'
};
