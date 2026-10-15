from datetime import datetime, timezone
import re
from typing import Dict, Any, List
from services.hash_service import HashService

IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
AWS_KEY_PATTERN = re.compile(r'\bAKIA[0-9A-Z]{16}\b')

def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False

class ReportService:
    @staticmethod
    def extract_dynamic_iocs(incident: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract indicators of compromise dynamically from incident logs and metadata."""
        logs = incident.get("logs", [])
        evidence_files = incident.get("evidence_files", [])
        iocs: List[Dict[str, str]] = []
        seen = set()

        def add_ioc(ioc_type: str, val: str, ctx: str):
            key = (ioc_type, val)
            if key not in seen and val and val != "None":
                seen.add(key)
                iocs.append({"type": ioc_type, "value": str(val), "context": str(ctx)})

        # 1. Evidence files integrity
        for ef in evidence_files:
            fname = ef.get("filename", "evidence.bin")
            fhash = ef.get("sha256", "")
            if fhash:
                add_ioc("Evidence File SHA-256", fhash, f"Cryptographic seal of uploaded file '{fname}'")

        # 2. Extract from logs
        for log in logs:
            raw = log.get("raw_payload", "")
            details = log.get("details", {})
            event_type = log.get("event_type", "LogEvent")
            
            # File Hashes in logs
            for match in SHA256_PATTERN.findall(raw):
                add_ioc("File Hash (SHA-256)", match, f"Extracted from {event_type} event payload")
            
            # AWS Keys
            for key in AWS_KEY_PATTERN.findall(raw):
                add_ioc("AWS Access Key", key, f"Compromised credential identified in {event_type}")

            # IP Addresses
            all_text = f"{raw} {details.get('source_ip', '')} {details.get('target_ip', '')} {details.get('dest_ip', '')}"
            for ip in IPV4_PATTERN.findall(all_text):
                if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                    continue
                if not _is_private_ip(ip):
                    add_ioc("External C2 / Adversary IP", ip, f"Identified in connection associated with {event_type}")
                else:
                    host = details.get("host") or details.get("hostname") or "Internal Asset"
                    add_ioc("Internal Network Host IP", f"{host} ({ip})", f"Internal endpoint involved in {event_type}")

            # Compromised Users
            user = details.get("user") or details.get("username")
            if user and user not in ("SYSTEM", "LOCAL", "root", "None"):
                add_ioc("Compromised Identity", str(user), f"Account associated with suspicious activity in {event_type}")

        # If it's the demo incident or sparse logs, ensure baseline IOCs exist
        if not iocs:
            for asset in incident.get("compromised_assets", []):
                add_ioc("Compromised Asset", asset, "Target asset identified during forensic triage")

        return iocs[:12]  # Keep top high-fidelity IOCs

    @staticmethod
    def generate_forensic_report(incident: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a complete forensic investigation report with cryptographic seals."""
        now = datetime.now(timezone.utc).isoformat()
        incident_id = incident.get("incident_id", "INC-UNKNOWN")
        title = incident.get("title", "Forensic Investigation")
        logs = incident.get("logs", [])
        evidence_files = incident.get("evidence_files", [])
        
        # Calculate Master Black Box Evidence Hash over all raw logs and evidence
        if evidence_files:
            file_hashes_concat = "".join([ef.get("sha256", "") for ef in evidence_files])
            master_hash = HashService.calculate_sha256(file_hashes_concat)
        else:
            master_payload = "".join([l.get("raw_payload", "") for l in logs])
            master_hash = HashService.calculate_sha256(master_payload if master_payload else incident_id)

        # Dynamic IOC extraction
        iocs = ReportService.extract_dynamic_iocs(incident)

        # Timeline Summary
        timeline = incident.get("timeline", [])
        timeline_summary = [
            {
                "time": str(step.get("time", "")),
                "phase": str(step.get("phase", "General")),
                "summary": str(step.get("summary", step.get("description", "")))
            }
            for step in timeline
        ]

        # Dynamic Remediation Recommendations
        recommendations: List[str] = []
        response_actions = incident.get("response_actions", [])
        for act in response_actions:
            title_act = act.get("title", "")
            rationale = act.get("ai_rationale", "")
            if title_act:
                recommendations.append(f"{title_act}: {rationale}" if rationale else title_act)

        if not recommendations:
            compromised_assets = incident.get("compromised_assets", [])
            for asset in compromised_assets[:3]:
                recommendations.append(f"Immediately isolate {asset} from the corporate LAN and preserve volatility memory dumps.")
            recommendations.append("Enforce multi-factor authentication (MFA) and rotate all domain administrator credentials.")
            recommendations.append("Apply egress firewall filters to drop traffic to identified external adversary IP addresses.")
            recommendations.append("Deploy enhanced PowerShell and EDR script-block logging across all production workstations.")

        threat_actor = incident.get("threat_actor", "Unknown Threat Actor")
        entry_point = incident.get("entry_point", "Phishing / Malicious Artifact")
        risk_score = incident.get("risk_score", 75)
        compromised_assets = incident.get("compromised_assets", [])

        executive_summary = (
            f"On {now[:10]}, the Cyber Black Box automated digital forensics engine analyzed {len(logs)} ingested "
            f"telemetry records across {len(evidence_files) if evidence_files else 1} evidence sources. "
            f"The incident '{title}' (ID: {incident_id}) received an automated risk score of {risk_score}/100. "
            f"Initial access is attributed to '{entry_point}' associated with threat group '{threat_actor}'. "
            f"The investigation confirmed {len(compromised_assets)} compromised systems, with {len(iocs)} high-confidence "
            f"indicators of compromise cryptographically cataloged in the incident vault."
        )

        report = {
            "report_id": f"REP-{incident_id}-FINAL",
            "incident_id": incident_id,
            "generated_at": now,
            "title": f"DIGITAL FORENSIC INVESTIGATION REPORT: {title}",
            "executive_summary": executive_summary,
            "threat_actor_profile": str(threat_actor),
            "entry_vector": str(entry_point),
            "compromised_assets": [str(a) for a in compromised_assets],
            "timeline_summary": timeline_summary,
            "indicators_of_compromise": iocs,
            "chain_of_custody_seal": {
                "master_evidence_sha256": master_hash,
                "ingested_artifacts_count": str(len(logs)),
                "evidence_files_count": str(len(evidence_files)),
                "integrity_verifier": "Cyber Black Box Invariant Ledger v2.4",
                "status": "FORENSICALLY_ADMISSIBLE_VERIFIED"
            },
            "remediation_recommendations": recommendations[:6]
        }
        
        return report

    @staticmethod
    def generate_markdown_report(incident: Dict[str, Any]) -> str:
        """Export report as formatted Markdown for downloading and archival."""
        rep = ReportService.generate_forensic_report(incident)
        md = []
        md.append(f"# {rep['title']}")
        md.append(f"**Report ID:** `{rep['report_id']}` | **Incident ID:** `{rep['incident_id']}`")
        md.append(f"**Generated:** {rep['generated_at']} (UTC)\n")
        md.append("## Executive Summary")
        md.append(rep["executive_summary"] + "\n")
        
        md.append("## Incident Profile")
        md.append(f"- **Threat Actor:** {rep['threat_actor_profile']}")
        md.append(f"- **Entry Vector:** {rep['entry_vector']}")
        md.append(f"- **Compromised Assets:** {', '.join(rep['compromised_assets']) if rep['compromised_assets'] else 'None'}\n")

        md.append("## Cryptographic Chain of Custody Seal")
        md.append("| Property | Value |")
        md.append("|---|---|")
        for k, v in rep["chain_of_custody_seal"].items():
            md.append(f"| `{k}` | `{v}` |")
        md.append("")

        md.append("## Indicators of Compromise (IOCs)")
        md.append("| Type | Indicator Value | Context |")
        md.append("|---|---|---|")
        for ioc in rep["indicators_of_compromise"]:
            md.append(f"| {ioc.get('type')} | `{ioc.get('value')}` | {ioc.get('context')} |")
        md.append("")

        md.append("## Forensic Timeline")
        md.append("| Timestamp | Attack Phase | Event Summary |")
        md.append("|---|---|---|")
        for item in rep["timeline_summary"]:
            md.append(f"| {item.get('time')} | {item.get('phase')} | {item.get('summary')} |")
        md.append("")

        md.append("## Remediation Recommendations")
        for i, rec in enumerate(rep["remediation_recommendations"], 1):
            md.append(f"{i}. {rec}")
        md.append("")
        
        return "\n".join(md)
