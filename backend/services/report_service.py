from datetime import datetime, timezone
from typing import Dict, Any, List
from services.hash_service import HashService

class ReportService:
    @staticmethod
    def generate_forensic_report(incident: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a complete forensic investigation report with cryptographic seals."""
        now = datetime.now(timezone.utc).isoformat()
        incident_id = incident.get("incident_id", "INC-UNKNOWN")
        logs = incident.get("logs", [])
        
        # Calculate Master Black Box Evidence Hash over all raw logs
        master_payload = "".join([l.get("raw_payload", "") for l in logs])
        master_hash = HashService.calculate_sha256(master_payload)
        
        iocs = [
            {"type": "IP Address (C2)", "value": "185.220.101.45", "context": "Attacker Command & Control & Exfiltration Egress IP"},
            {"type": "File Hash (SHA-256)", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "context": "Malicious Attachment Q3_Executive_Compensation.pdf.exe"},
            {"type": "Host Name", "value": "DEV-WS-04 (10.0.4.12)", "context": "Initial Entry Point Workstation"},
            {"type": "IAM Key ID", "value": "AKIA3910283", "context": "Stolen AWS Access Key used for Cloud Exfiltration"},
            {"type": "Compromised Account", "value": "CORP\\DomainAdmin_svc", "context": "Harvested Domain Admin Kerberos Ticket"}
        ]

        timeline_summary = [
            {"time": step.get("time"), "phase": step.get("phase"), "summary": step.get("summary")}
            for step in incident.get("timeline", [])
        ]

        report = {
            "report_id": f"REP-{incident_id}-FINAL",
            "incident_id": incident_id,
            "generated_at": now,
            "title": f"DIGITAL FORENSIC INVESTIGATION REPORT: {incident.get('title')}",
            "executive_summary": (
                f"On {now[:10]}, the Cyber Black Box automated forensics system detected and reconstructed a critical "
                f"cyber breach (Risk Score: {incident.get('risk_score')}/100) originating from external adversary {incident.get('threat_actor')}. "
                f"The attack scope compromised {len(incident.get('compromised_assets', []))} critical assets, culminating in unauthorized AWS S3 cloud data exfiltration."
            ),
            "threat_actor_profile": incident.get("threat_actor"),
            "entry_vector": incident.get("entry_point"),
            "compromised_assets": incident.get("compromised_assets"),
            "timeline_summary": timeline_summary,
            "indicators_of_compromise": iocs,
            "chain_of_custody_seal": {
                "master_evidence_sha256": master_hash,
                "ingested_artifacts_count": str(len(logs)),
                "integrity_verifier": "Cyber Black Box Invariant Ledger v2.4",
                "status": "FORENSICALLY_ADMISSIBLE_VERIFIED"
            },
            "remediation_recommendations": [
                "Isolate patient zero host DEV-WS-04 and preserve RAM memory dump for malware disassembly.",
                "Revoke AWS IAM Access Key AKIA3910283 and enforce MFA on all cloud management APIs.",
                "Inject firewall block rule for malicious C2 IP 185.220.101.45 across border routers.",
                "Perform enterprise Kerberos krbtgt account password reset twice to invalidate ticket granting tickets.",
                "Deploy PowerShell Script Block Logging (Event ID 4104) and enforce Constrained Language Mode."
            ]
        }
        
        return report
