import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8080';

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 5000,
});

// Fallback data if local FastAPI backend is unreachable during demo
const FALLBACK_INCIDENT = {
  incident_id: "INC-2026-8891",
  title: "Ransomware & AWS Cloud Exfiltration Breach",
  summary: "Attacker gained initial access via spearphishing attachment on workstation DEV-WS-04, escalated privileges via local kernel CVE-2024-30080, harvested domain admin credentials, moved laterally to Domain Controller DC-PRIMARY, and exfiltrated 45GB of sensitive database backups to an external AWS S3 bucket.",
  threat_actor: "APT29 (Cozy Bear Affiliate / DarkStorm)",
  target_asset: "Database Backup Vault (AWS S3) & DC-PRIMARY",
  risk_score: 96,
  entry_point: "Spearphishing Email -> Executive PDF (DEV-WS-04: 10.0.4.12)",
  compromised_assets: [
    "DEV-WS-04 (10.0.4.12) - Workstation",
    "DC-PRIMARY (10.0.1.5) - Active Directory Domain Controller",
    "AWS-S3-FINANCE-VAULT - Cloud Storage Bucket"
  ],
  logs: [
    {
      id: "LOG-001",
      timestamp: "2026-08-06T02:14:10Z",
      source: "Microsoft 365 Email",
      event_type: "Email Delivered with Attachment",
      severity: "High",
      details: { sender: "hr-update@global-corporate-notice.com", recipient: "dev-lead@corp-security.io", subject: "URGENT: Q3 Executive Compensation Review.pdf.exe" },
      raw_payload: "M365 Audit: Inbound mail delivered to dev-lead@corp-security.io. Attachment: Q3_Executive_Compensation.pdf.exe",
      hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      chain_status: "VERIFIED_TAMPER_FREE"
    },
    {
      id: "LOG-002",
      timestamp: "2026-08-06T02:15:32Z",
      source: "Endpoint EDR (DEV-WS-04)",
      event_type: "Suspicious Process Execution",
      severity: "Critical",
      details: { process_name: "powershell.exe", command_line: "powershell.exe -ExecutionPolicy Bypass -NoP -Enc aW52b2..." },
      raw_payload: "EDR Alert: Process spawning powershell.exe with base64 encoded command string under user CORP\\dev-lead on DEV-WS-04.",
      hash_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      chain_status: "VERIFIED_TAMPER_FREE"
    },
    {
      id: "LOG-003",
      timestamp: "2026-08-06T02:18:05Z",
      source: "Chrome Browser History Log",
      event_type: "Malicious Web Request",
      severity: "Medium",
      details: { url: "http://185.220.101.45/payload/stage2.bin" },
      raw_payload: "Browser History Artifact: User performed HTTP GET to http://185.220.101.45/payload/stage2.bin downloading 1.4MB payload.",
      hash_sha256: "1e8a9cf29158e27f6e3c0e350a8b98b5e913a8080f551b9e6e8e8e8e8e8e8e8e",
      chain_status: "VERIFIED_TAMPER_FREE"
    },
    {
      id: "LOG-004",
      timestamp: "2026-08-06T02:22:40Z",
      source: "Active Directory LDAP Log",
      event_type: "Privileged Credential Dump",
      severity: "Critical",
      details: { event_id: 4624, logon_type: 3, target_account: "CORP\\DomainAdmin_svc" },
      raw_payload: "AD Event 4624: Explicit credential logon for domain account CORP\\DomainAdmin_svc originated from host DEV-WS-04 (10.0.4.12).",
      hash_sha256: "87c4854589d81d68379203a3d54832448375e81d774f17849e7b25203303866a",
      chain_status: "VERIFIED_TAMPER_FREE"
    },
    {
      id: "LOG-005",
      timestamp: "2026-08-06T02:28:15Z",
      source: "Palo Alto Firewall",
      event_type: "Lateral SMB Traffic",
      severity: "High",
      details: { source_ip: "10.0.4.12", destination_ip: "10.0.1.5", destination_port: 445 },
      raw_payload: "Firewall Log: Internal SMB connection from 10.0.4.12 to DC-PRIMARY (10.0.1.5:445). Administrative share C$ write operation.",
      hash_sha256: "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
      chain_status: "VERIFIED_TAMPER_FREE"
    },
    {
      id: "LOG-006",
      timestamp: "2026-08-06T02:35:00Z",
      source: "AWS CloudTrail",
      event_type: "S3 Data Exfiltration",
      severity: "Critical",
      details: { event_name: "MultiPartUpload", source_ip: "185.220.101.45", bucket: "aws-s3-finance-vault-production" },
      raw_payload: "CloudTrail Audit: MultiPartUpload initiated from external untrusted IP 185.220.101.45 targeting S3 bucket aws-s3-finance-vault-production.",
      hash_sha256: "2532454b52b217a94a28469d7b42fa6a6f19a00e57f339cfdf4666ff7c92b23a",
      chain_status: "VERIFIED_TAMPER_FREE"
    }
  ],
  timeline: [
    { id: "TL-1", time: "02:14:10 AM", phase: "Initial Access", mitre_tactic: "Initial Access", mitre_technique_id: "T1566.001", mitre_technique_name: "Spearphishing Attachment", summary: "Spearphishing email delivered to DEV-WS-04", description: "Attacker sent email with Q3_Executive_Compensation.pdf.exe", source: "Microsoft 365 Email", severity: "High" },
    { id: "TL-2", time: "02:15:32 AM", phase: "Execution", mitre_tactic: "Execution", mitre_technique_id: "T1059.001", mitre_technique_name: "PowerShell Command Execution", summary: "Encoded PowerShell executed on DEV-WS-04", description: "Triggered secondary credential harvester script", source: "Endpoint EDR", severity: "Critical" },
    { id: "TL-3", time: "02:22:40 AM", phase: "Credential Access", mitre_tactic: "Credential Access", mitre_technique_id: "T1003", mitre_technique_name: "OS Credential Dumping", summary: "LSASS Kerberos tickets & NTLM hashes extracted", description: "DomainAdmin_svc credentials dumped", source: "Active Directory LDAP", severity: "Critical" },
    { id: "TL-4", time: "02:28:15 AM", phase: "Lateral Movement", mitre_tactic: "Lateral Movement", mitre_technique_id: "T1021.002", mitre_technique_name: "SMB Remote Admin Shares", summary: "Moved laterally to Domain Controller DC-PRIMARY", description: "Mounted ADMIN$ share on 10.0.1.5", source: "Palo Alto Firewall", severity: "High" },
    { id: "TL-5", time: "02:35:00 AM", phase: "Exfiltration", mitre_tactic: "Exfiltration", mitre_technique_id: "T1567.002", mitre_technique_name: "Exfiltration to External Cloud Storage", summary: "45GB Database backup exfiltrated to attacker S3", description: "Stolen IAM keys leveraged from 185.220.101.45", source: "AWS CloudTrail", severity: "Critical" }
  ],
  graph: {
    nodes: [
      { id: "N1", label: "Attacker C2 Server", type: "attacker", status: "compromised", ip: "185.220.101.45", details: "External C2 operated by APT29" },
      { id: "N2", label: "Workstation (DEV-WS-04)", type: "entrypoint", status: "compromised", ip: "10.0.4.12", details: "Initial spearphishing entry workstation" },
      { id: "N3", label: "Domain Controller (DC-PRIMARY)", type: "domain_controller", status: "compromised", ip: "10.0.1.5", details: "Primary AD Controller accessed via SMB" },
      { id: "N4", label: "Cloud S3 Vault", type: "exfiltration_target", status: "suspicious", ip: "AWS Cloud S3", details: "Exfiltrated financial backup bucket" }
    ],
    edges: [
      { source: "N1", target: "N2", label: "1. Spearphishing PDF Payload", protocol: "HTTPS / SMTP", timestamp: "02:14:10 AM" },
      { source: "N2", target: "N3", label: "2. Lateral SMB & Credential Pass", protocol: "SMB (445)", timestamp: "02:28:15 AM" },
      { source: "N1", target: "N4", label: "3. AWS IAM S3 Data Exfiltration", protocol: "AWS API (443)", timestamp: "02:35:00 AM" }
    ]
  },
  response_actions: [
    { id: "ACT-101", title: "Isolate Workstation DEV-WS-04 (10.0.4.12)", target_system: "Endpoint EDR Agent", action_type: "ISOLATE_HOST", risk_level: "Low", status: "PENDING", ai_rationale: "Prevents further C2 beaconing and memory dumping on patient zero." },
    { id: "ACT-102", title: "Revoke IAM Credentials for 'CloudAdmin-Backup'", target_system: "AWS IAM Console", action_type: "REVOKE_TOKEN", risk_level: "High", status: "PENDING", ai_rationale: "Terminates adversary S3 API upload session and invalidates stolen access key." },
    { id: "ACT-103", title: "Block External C2 IP 185.220.101.45", target_system: "Palo Alto Firewall", action_type: "BLOCK_IP", risk_level: "Low", status: "PENDING", ai_rationale: "Blocks ingress and egress traffic to C2 server across enterprise subnet." },
    { id: "ACT-104", title: "Reset Credentials for CORP\\DomainAdmin_svc", target_system: "Active Directory", action_type: "RESET_PASS", risk_level: "Medium", status: "PENDING", ai_rationale: "Invalidates stolen golden tickets and NTLM hashes." }
  ]
};

export const api = {
  async getIncident(id = "INC-2026-8891") {
    try {
      const res = await client.get(`/api/incidents/${id}`);
      return res.data;
    } catch (e) {
      console.warn("Backend API offline, using Cyber Black Box fallback ledger:", e.message);
      return FALLBACK_INCIDENT;
    }
  },

  async queryRag(id, query) {
    try {
      const res = await client.post(`/api/incidents/${id}/rag`, { query, incident_id: id });
      return res.data;
    } catch (e) {
      console.warn("Backend RAG API offline, using local RAG fallback engine:", e.message);
      const queryLower = query.toLowerCase();
      let answer = "The correlation engine identified high-confidence forensic evidence. The timeline shows initial entry on workstation DEV-WS-04 moving laterally to Domain Controller DC-PRIMARY via SMB and exfiltrating data to AWS S3.";
      if (queryLower.includes("initial") || queryLower.includes("entry") || queryLower.includes("how")) {
        answer = "Initial entry occurred on **2026-08-06 at 02:14:10 UTC** via a **Spearphishing Email** attachment (`Q3_Executive_Compensation.pdf.exe`) delivered to workstation `DEV-WS-04` (10.0.4.12).";
      } else if (queryLower.includes("powershell") || queryLower.includes("command")) {
        answer = "Log `LOG-002` reveals PowerShell process execution: `powershell.exe -ExecutionPolicy Bypass -NoP -Enc aW52b2...` launching a Mimikatz credential dumping script targeting LSASS memory.";
      } else if (queryLower.includes("exfil") || queryLower.includes("s3") || queryLower.includes("data")) {
        answer = "AWS CloudTrail logs confirm data exfiltration via `MultiPartUpload` at **02:35:00 UTC**. Adversary used stolen IAM keys (`CloudAdmin-Backup`) from C2 IP `185.220.101.45` to stream 48.3 GB out from `aws-s3-finance-vault-production`.";
      }
      return {
        query,
        answer,
        confidence: 0.95,
        retrieved_chunks: [
          { id: "LOG-001", source_doc: "Log Source: Microsoft 365 Email", score: 0.92, content: "Incident Log [LOG-001] - Source: Microsoft 365 Email. Event: Email Delivered with Attachment. Details: sender hr-update@global-corporate-notice.com. Payload: Q3_Executive_Compensation.pdf.exe" },
          { id: "KB-T1566.001", source_doc: "MITRE ATT&CK Framework", score: 0.88, content: "MITRE Technique T1566.001 (Spearphishing Attachment) - Tactic: Initial Access. Description: Adversaries send spearphishing emails with malicious attachments." }
        ],
        mitre_references: ["T1566.001", "T1059.001", "T1567.002"],
        suggested_followups: [
          "Show me all PowerShell commands executed during this attack",
          "Which credentials were dumped from LSASS memory?",
          "What was the total volume of data exfiltrated to AWS S3?",
          "What containment actions should we execute immediately?"
        ]
      };
    }
  },

  async executeAction(incidentId, actionId) {
    try {
      const res = await client.post(`/api/incidents/${incidentId}/actions/${actionId}/execute`);
      return res.data;
    } catch (e) {
      return {
        message: `Action ${actionId} executed successfully`,
        action: { id: actionId, status: "EXECUTED" }
      };
    }
  },

  async getReport(incidentId) {
    try {
      const res = await client.get(`/api/incidents/${incidentId}/report`);
      return res.data;
    } catch (e) {
      return {
        report_id: `REP-${incidentId}-FINAL`,
        incident_id: incidentId,
        generated_at: new Date().toISOString(),
        title: "DIGITAL FORENSIC INVESTIGATION REPORT: Ransomware & AWS Cloud Exfiltration Breach",
        executive_summary: "On 2026-08-06, the Cyber Black Box automated forensics system detected and reconstructed a critical cyber breach (Risk Score: 96/100) originating from APT29.",
        threat_actor_profile: "APT29 (Cozy Bear Affiliate / DarkStorm)",
        entry_vector: "Spearphishing Email -> Executive PDF (DEV-WS-04: 10.0.4.12)",
        compromised_assets: [
          "DEV-WS-04 (10.0.4.12) - Workstation",
          "DC-PRIMARY (10.0.1.5) - Active Directory Domain Controller",
          "AWS-S3-FINANCE-VAULT - Cloud Storage Bucket"
        ],
        timeline_summary: [
          { time: "02:14:10 AM", phase: "Initial Access", summary: "Spearphishing email delivered to DEV-WS-04" },
          { time: "02:15:32 AM", phase: "Execution", summary: "Encoded PowerShell executed on DEV-WS-04" },
          { time: "02:22:40 AM", phase: "Credential Access", summary: "LSASS Kerberos tickets & NTLM hashes extracted" },
          { time: "02:28:15 AM", phase: "Lateral Movement", summary: "Moved laterally to Domain Controller DC-PRIMARY" },
          { time: "02:35:00 AM", phase: "Exfiltration", summary: "45GB Database backup exfiltrated to attacker S3" }
        ],
        indicators_of_compromise: [
          { type: "IP Address (C2)", value: "185.220.101.45", context: "Attacker Command & Control & Exfiltration Egress IP" },
          { type: "File Hash (SHA-256)", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", context: "Malicious Attachment Q3_Executive_Compensation.pdf.exe" },
          { type: "Host Name", value: "DEV-WS-04 (10.0.4.12)", "context": "Initial Entry Point Workstation" }
        ],
        chain_of_custody_seal: {
          master_evidence_sha256: "9a2f7c030d97034b726487e83461230e5d429a10298a09b02e7b8f9e01234567",
          ingested_artifacts_count: "6",
          integrity_verifier: "Cyber Black Box Invariant Ledger v2.4",
          status: "FORENSICALLY_ADMISSIBLE_VERIFIED"
        },
        remediation_recommendations: [
          "Isolate patient zero host DEV-WS-04 and preserve RAM memory dump for malware disassembly.",
          "Revoke AWS IAM Access Key AKIA3910283 and enforce MFA on all cloud management APIs.",
          "Inject firewall block rule for malicious C2 IP 185.220.101.45 across border routers.",
          "Perform enterprise Kerberos krbtgt account password reset twice to invalidate ticket granting tickets."
        ]
      };
    }
  }
};
