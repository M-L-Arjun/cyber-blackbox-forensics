from typing import Dict, Any

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "INC-2026-8891": {
        "incident_id": "INC-2026-8891",
        "title": "Ransomware & AWS Cloud Exfiltration Breach",
        "summary": "Attacker gained initial access via spearphishing attachment on workstation DEV-WS-04, escalated privileges via local kernel CVE-2024-30080, harvested domain admin credentials, moved laterally to Domain Controller DC-PRIMARY, and exfiltrated 45GB of sensitive database backups to an external AWS S3 bucket.",
        "threat_actor": "APT29 (Cozy Bear Affiliate / DarkStorm)",
        "target_asset": "Database Backup Vault (AWS S3) & DC-PRIMARY",
        "risk_score": 96,
        "entry_point": "Spearphishing Email -> Executive PDF (DEV-WS-04: 10.0.4.12)",
        "compromised_assets": [
            "DEV-WS-04 (10.0.4.12) - Workstation",
            "DC-PRIMARY (10.0.1.5) - Active Directory Domain Controller",
            "AWS-S3-FINANCE-VAULT - Cloud Storage Bucket"
        ],
        "logs": [
            {
                "id": "LOG-001",
                "timestamp": "2026-08-06T02:14:10Z",
                "source": "Microsoft 365 Email",
                "event_type": "Email Delivered with Attachment",
                "severity": "High",
                "details": {
                    "sender": "hr-update@global-corporate-notice.com",
                    "recipient": "dev-lead@corp-security.io",
                    "subject": "URGENT: Q3 Executive Compensation Review.pdf.exe",
                    "attachment_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "raw_payload": "M365 Audit: Inbound mail delivered to dev-lead@corp-security.io. Sender IP: 185.220.101.45. Attachment name: Q3_Executive_Compensation.pdf.exe (executable header detected)."
            },
            {
                "id": "LOG-002",
                "timestamp": "2026-08-06T02:15:32Z",
                "source": "Endpoint EDR (DEV-WS-04)",
                "event_type": "Suspicious Process Execution",
                "severity": "Critical",
                "details": {
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -ExecutionPolicy Bypass -NoP -Enc aW52b2tlLW1pbWlrYXR6IC1jYW1wYWlnbiBzeXN0ZW0=",
                    "parent_process": "Q3_Executive_Compensation.exe",
                    "user": "CORP\\dev-lead"
                },
                "raw_payload": "EDR Alert: Process spawning powershell.exe with base64 encoded command string under user CORP\\dev-lead on DEV-WS-04."
            },
            {
                "id": "LOG-003",
                "timestamp": "2026-08-06T02:18:05Z",
                "source": "Chrome Browser History Log",
                "event_type": "Malicious Web Request",
                "severity": "Medium",
                "details": {
                    "url": "http://185.220.101.45/payload/stage2.bin",
                    "referrer": "chrome-extension://pdf-viewer",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },
                "raw_payload": "Browser History Artifact: User performed HTTP GET to http://185.220.101.45/payload/stage2.bin downloading 1.4MB binary payload."
            },
            {
                "id": "LOG-004",
                "timestamp": "2026-08-06T02:22:40Z",
                "source": "Active Directory LDAP Log",
                "event_type": "Privileged Credential Dump",
                "severity": "Critical",
                "details": {
                    "event_id": 4624,
                    "logon_type": 3,
                    "target_account": "CORP\\DomainAdmin_svc",
                    "workstation_name": "DEV-WS-04",
                    "ip_address": "10.0.4.12"
                },
                "raw_payload": "AD Event 4624: Explicit credential logon for privileged domain account CORP\\DomainAdmin_svc originated from host DEV-WS-04 (10.0.4.12)."
            },
            {
                "id": "LOG-005",
                "timestamp": "2026-08-06T02:28:15Z",
                "source": "Palo Alto Firewall",
                "event_type": "Lateral SMB Traffic",
                "severity": "High",
                "details": {
                    "source_ip": "10.0.4.12",
                    "destination_ip": "10.0.1.5",
                    "destination_port": 445,
                    "protocol": "SMB",
                    "bytes_transferred": 1450200
                },
                "raw_payload": "Firewall Log: Internal SMB connection from 10.0.4.12 to DC-PRIMARY (10.0.1.5:445). Administrative share C$ write operation."
            },
            {
                "id": "LOG-006",
                "timestamp": "2026-08-06T02:35:00Z",
                "source": "AWS CloudTrail",
                "event_type": "S3 Data Exfiltration",
                "severity": "Critical",
                "details": {
                    "event_name": "PutObject / MultiPartUpload",
                    "user_identity": "arn:aws:iam::88291039:user/CloudAdmin-Backup",
                    "source_ip": "185.220.101.45",
                    "bucket": "aws-s3-finance-vault-production",
                    "bytes_uploaded": "48318382080"
                },
                "raw_payload": "CloudTrail Audit: MultiPartUpload initiated from external untrusted IP 185.220.101.45 targeting S3 bucket aws-s3-finance-vault-production using stolen IAM access key AKIA3910283."
            }
        ],
        "timeline": [
            {
                "id": "TL-1",
                "time": "02:14:10 AM",
                "phase": "Initial Access",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1566.001",
                "mitre_technique_name": "Spearphishing Attachment",
                "summary": "Malicious email attachment delivered to dev-lead@corp-security.io",
                "description": "Attacker sent spearphishing email with payload Q3_Executive_Compensation.pdf.exe from spoofed external domain.",
                "source": "Microsoft 365 Email",
                "evidence_ids": ["LOG-001"],
                "severity": "High"
            },
            {
                "id": "TL-2",
                "time": "02:15:32 AM",
                "phase": "Execution",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059.001",
                "mitre_technique_name": "PowerShell Command Execution",
                "summary": "Base64 encoded PowerShell script executed on DEV-WS-04",
                "description": "User opened malicious attachment, triggering hidden powershell process to invoke secondary credential harvester.",
                "source": "Endpoint EDR",
                "evidence_ids": ["LOG-002", "LOG-003"],
                "severity": "Critical"
            },
            {
                "id": "TL-3",
                "time": "02:22:40 AM",
                "phase": "Credential Access",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1003",
                "mitre_technique_name": "OS Credential Dumping",
                "summary": "DomainAdmin_svc Kerberos tickets & NTLM hashes extracted",
                "description": "LSASS memory was dumped on DEV-WS-04, granting attacker Domain Admin credentials.",
                "source": "Active Directory LDAP",
                "evidence_ids": ["LOG-004"],
                "severity": "Critical"
            },
            {
                "id": "TL-4",
                "time": "02:28:15 AM",
                "phase": "Lateral Movement",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique_id": "T1021.002",
                "mitre_technique_name": "SMB Remote Administrative Shares",
                "summary": "Attacker moved laterally to Domain Controller DC-PRIMARY",
                "description": "Using stolen DomainAdmin credentials, attacker mounted ADMIN$ share on 10.0.1.5.",
                "source": "Palo Alto Firewall",
                "evidence_ids": ["LOG-005"],
                "severity": "High"
            },
            {
                "id": "TL-5",
                "time": "02:35:00 AM",
                "phase": "Exfiltration",
                "mitre_tactic": "Exfiltration",
                "mitre_technique_id": "T1567.002",
                "mitre_technique_name": "Exfiltration to External Cloud Storage",
                "summary": "45GB Database backup exfiltrated to attacker S3 storage",
                "description": "Stolen IAM keys were leveraged from C2 IP 185.220.101.45 to stream financial database backups out.",
                "source": "AWS CloudTrail",
                "evidence_ids": ["LOG-006"],
                "severity": "Critical"
            }
        ],
        "graph": {
            "nodes": [
                {
                    "id": "N1",
                    "label": "Attacker C2 Server",
                    "type": "attacker",
                    "status": "compromised",
                    "ip": "185.220.101.45",
                    "details": "External malicious Command & Control server operated by APT29"
                },
                {
                    "id": "N2",
                    "label": "Workstation (DEV-WS-04)",
                    "type": "entrypoint",
                    "status": "compromised",
                    "ip": "10.0.4.12",
                    "details": "Initial entry workstation where spearphishing attachment was executed"
                },
                {
                    "id": "N3",
                    "label": "Domain Controller (DC-PRIMARY)",
                    "type": "domain_controller",
                    "status": "compromised",
                    "ip": "10.0.1.5",
                    "details": "Primary Active Directory Server accessed via lateral SMB connection"
                },
                {
                    "id": "N4",
                    "label": "Cloud S3 Vault",
                    "type": "exfiltration_target",
                    "status": "suspicious",
                    "ip": "AWS Cloud S3",
                    "details": "Financial database backup storage bucket exfiltrated to adversary storage"
                }
            ],
            "edges": [
                {
                    "source": "N1",
                    "target": "N2",
                    "label": "1. Spearphishing PDF / HTTP C2",
                    "protocol": "HTTPS / SMTP",
                    "timestamp": "02:14:10 AM"
                },
                {
                    "source": "N2",
                    "target": "N3",
                    "label": "2. Lateral SMB & Credential Pass",
                    "protocol": "SMB (445)",
                    "timestamp": "02:28:15 AM"
                },
                {
                    "source": "N1",
                    "target": "N4",
                    "label": "3. AWS IAM S3 Data Exfiltration",
                    "protocol": "AWS API (443)",
                    "timestamp": "02:35:00 AM"
                }
            ]
        },
        "response_actions": [
            {
                "id": "ACT-101",
                "title": "Isolate Workstation DEV-WS-04 (10.0.4.12)",
                "target_system": "Endpoint EDR Agent",
                "action_type": "ISOLATE_HOST",
                "risk_level": "Low",
                "status": "PENDING",
                "ai_rationale": "Prevents further C2 beaconing and memory dumping on initial patient zero machine."
            },
            {
                "id": "ACT-102",
                "title": "Revoke IAM Credentials for 'CloudAdmin-Backup'",
                "target_system": "AWS IAM Console",
                "action_type": "REVOKE_TOKEN",
                "risk_level": "High",
                "status": "PENDING",
                "ai_rationale": "Immediately terminates adversary S3 upload API session and invalidates stolen access key AKIA3910283."
            },
            {
                "id": "ACT-103",
                "title": "Block External C2 IP 185.220.101.45",
                "target_system": "Palo Alto Perimeter Firewall",
                "action_type": "BLOCK_IP",
                "risk_level": "Low",
                "status": "PENDING",
                "ai_rationale": "Blocks ingress and egress traffic to attacker command & control node across entire enterprise subnet."
            },
            {
                "id": "ACT-104",
                "title": "Force Password & Kerberos Ticket Reset for CORP\\DomainAdmin_svc",
                "target_system": "Active Directory",
                "action_type": "RESET_PASS",
                "risk_level": "Medium",
                "status": "PENDING",
                "ai_rationale": "Invalidates stolen golden tickets and NTLM hashes used for lateral SMB authentication."
            }
        ]
    }
}
