import re
import csv
import json
import io
import hashlib
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
from services.hash_service import HashService

MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB limit

# Common IP Regex
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# ISO / Standard timestamp patterns
ISO_TIMESTAMP_REGEX = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
SYSLOG_TIMESTAMP_REGEX = re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b')
TIME_ONLY_REGEX = re.compile(r'\b\d{1,2}:\d{2}:\d{2}(?:\s*(?:AM|PM|am|pm))?\b')

class ParserService:
    @staticmethod
    def validate_file_bytes(content: bytes, filename: str) -> str:
        """Validate file size and text encoding, returning decoded text string."""
        if not content or len(content.strip()) == 0:
            raise ValueError(f"File '{filename}' is empty.")
            
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File '{filename}' exceeds maximum size limit of {MAX_FILE_SIZE_BYTES // (1024*1024)}MB.")

        # Quick binary check: excessive null bytes indicate compiled binary or media
        null_count = content[:1024].count(b'\x00')
        if null_count > 20 and not (filename.endswith('.pdf') or filename.endswith('.exe')):
            raise ValueError(f"File '{filename}' appears to be a binary executable or corrupt data.")

        # Try multiple text encodings
        for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'utf-16']:
            try:
                return content.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue

        raise ValueError(f"Could not decode '{filename}' using standard UTF-8, Latin-1, or UTF-16 encodings.")

    @staticmethod
    def compute_sha256(content: bytes) -> str:
        """Compute exact SHA-256 hash digest directly from raw file bytes."""
        return hashlib.sha256(content).hexdigest()

    @classmethod
    def parse_file_bytes(cls, content: bytes, filename: str, file_id: str = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        import uuid
        if not file_id:
            file_id = f"EV-{uuid.uuid4().hex[:8]}"
        return cls.parse_file(filename=filename, content=content, file_id=file_id)

    @classmethod
    def parse_file(cls, filename: str, content: bytes, file_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Validate, parse and normalize records from TXT, CSV, JSON, or JSONL files.
        Returns:
            (parsed_logs, file_metadata)
        """
        file_sha256 = cls.compute_sha256(content)
        decoded_text = cls.validate_file_bytes(content, filename)
        ext = filename.lower().split('.')[-1] if '.' in filename else 'txt'
        now_iso = datetime.now(timezone.utc).isoformat()

        parsed_logs: List[Dict[str, Any]] = []

        if ext == 'csv':
            parsed_logs = cls._parse_csv(decoded_text, filename, file_id, now_iso)
        elif ext in ['json', 'jsonl', 'ndjson']:
            parsed_logs = cls._parse_json_or_jsonl(decoded_text, filename, file_id, now_iso)
        else:
            # Default to TXT / Syslog / EDR text parser
            parsed_logs = cls._parse_text(decoded_text, filename, file_id, now_iso)

        if not parsed_logs:
            raise ValueError(f"No parseable forensic event records could be extracted from '{filename}'.")

        # Attach cryptographic SHA-256 seal to each log entry
        sealed_logs = []
        for log in parsed_logs:
            sealed = HashService.process_log_entry(log)
            sealed_logs.append(sealed)

        metadata = {
            "id": file_id,
            "filename": filename,
            "file_sha256": file_sha256,
            "sha256": file_sha256,
            "file_size_bytes": len(content),
            "content_type": f"text/{ext}",
            "records_count": len(sealed_logs),
            "record_count": len(sealed_logs),
            "uploaded_at": now_iso,
            "ingested_at": now_iso
        }

        return sealed_logs, metadata

    @classmethod
    def _parse_csv(cls, text: str, filename: str, file_id: str, default_time: str) -> List[Dict[str, Any]]:
        logs = []
        reader = csv.DictReader(io.StringIO(text))
        
        # If reader has no fieldnames, raise error
        if not reader.fieldnames:
            raise ValueError(f"CSV file '{filename}' has no header columns.")

        # Clean field names
        fieldnames = [f.strip() if f else "" for f in reader.fieldnames]

        for idx, row in enumerate(reader):
            # Find timestamp
            timestamp = default_time
            for col in ['timestamp', 'time', 'date', 'datetime', 'created_at', 'Date']:
                if col in row and row[col]:
                    timestamp = row[col].strip()
                    break

            # Find source
            source = f"CSV Evidence: {filename}"
            for col in ['source', 'src', 'device', 'channel', 'service', 'system']:
                if col in row and row[col]:
                    source = row[col].strip()
                    break

            # Find event_type
            event_type = "Network/Audit Telemetry"
            for col in ['event_type', 'event', 'action', 'Action', 'type', 'command', 'status']:
                if col in row and row[col]:
                    event_type = row[col].strip()
                    break

            # Infer severity
            row_str = " ".join([str(v) for v in row.values()]).lower()
            severity = cls._infer_severity(row_str)

            # Details
            details = {k: v.strip() if isinstance(v, str) else v for k, v in row.items() if k and v}

            log_entry = {
                "id": f"EV-{file_id[:8]}-{idx+1:04d}",
                "evidence_file_id": file_id,
                "timestamp": timestamp,
                "source": source,
                "event_type": event_type,
                "severity": severity,
                "details": details,
                "raw_payload": f"[{filename} line {idx+2}] " + ", ".join([f"{k}={v}" for k, v in details.items()])
            }
            logs.append(log_entry)

        return logs

    @classmethod
    def _parse_json_or_jsonl(cls, text: str, filename: str, file_id: str, default_time: str) -> List[Dict[str, Any]]:
        logs = []
        stripped = text.strip()

        # Check if JSON array or AWS CloudTrail format
        if stripped.startswith('[') or stripped.startswith('{'):
            try:
                parsed_json = json.loads(stripped)
                if isinstance(parsed_json, list):
                    for idx, item in enumerate(parsed_json):
                        if isinstance(item, dict):
                            logs.append(cls._normalize_json_record(item, filename, file_id, idx, default_time))
                    return logs
                elif isinstance(parsed_json, dict):
                    # Check AWS CloudTrail / Azure Records array
                    if "Records" in parsed_json and isinstance(parsed_json["Records"], list):
                        for idx, item in enumerate(parsed_json["Records"]):
                            if isinstance(item, dict):
                                logs.append(cls._normalize_json_record(item, filename, file_id, idx, default_time))
                        return logs
                    # Check events array
                    for key in ["events", "logs", "items", "entries"]:
                        if key in parsed_json and isinstance(parsed_json[key], list):
                            for idx, item in enumerate(parsed_json[key]):
                                if isinstance(item, dict):
                                    logs.append(cls._normalize_json_record(item, filename, file_id, idx, default_time))
                            return logs
                    # Single object
                    logs.append(cls._normalize_json_record(parsed_json, filename, file_id, 0, default_time))
                    return logs
            except json.JSONDecodeError:
                pass  # Try JSONL below

        # Process as JSON Lines (one JSON per line)
        line_idx = 0
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                if isinstance(obj, dict):
                    logs.append(cls._normalize_json_record(obj, filename, file_id, line_idx, default_time))
                    line_idx += 1
            except json.JSONDecodeError:
                continue

        return logs

    @classmethod
    def _normalize_json_record(cls, item: Dict[str, Any], filename: str, file_id: str, idx: int, default_time: str) -> Dict[str, Any]:
        # Extract timestamp
        timestamp = default_time
        for key in ['eventTime', 'timestamp', 'time', 'date', 'Timestamp', 'EventTime', 'created_at']:
            if key in item and item[key]:
                timestamp = str(item[key])
                break

        # Extract source
        source = f"Cloud/API Audit: {filename}"
        for key in ['eventSource', 'source', 'system', 'service', 'appName', 'logname']:
            if key in item and item[key]:
                source = str(item[key])
                break

        # Extract event_type
        event_type = "API / Audit Event"
        for key in ['eventName', 'event_type', 'action', 'type', 'activity', 'operationName']:
            if key in item and item[key]:
                event_type = str(item[key])
                break

        item_str = json.dumps(item).lower()
        severity = cls._infer_severity(item_str)

        # Merge nested details dictionary if present for convenient access
        merged_details = dict(item)
        if isinstance(item.get("details"), dict):
            merged_details.update(item["details"])

        return {
            "id": f"EV-{file_id[:8]}-{idx+1:04d}",
            "evidence_file_id": file_id,
            "timestamp": timestamp,
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "details": merged_details,
            "raw_payload": json.dumps(item)
        }

    @classmethod
    def _parse_text(cls, text: str, filename: str, file_id: str, default_time: str) -> List[Dict[str, Any]]:
        logs = []
        lines = text.splitlines()

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # Extract timestamp
            timestamp = default_time
            iso_match = ISO_TIMESTAMP_REGEX.search(line_str)
            if iso_match:
                timestamp = iso_match.group(0)
            else:
                syslog_match = SYSLOG_TIMESTAMP_REGEX.search(line_str)
                if syslog_match:
                    timestamp = f"{datetime.now(timezone.utc).year} {syslog_match.group(0)}"
                else:
                    time_match = TIME_ONLY_REGEX.search(line_str)
                    if time_match:
                        timestamp = time_match.group(0)

            # Infer severity
            severity = cls._infer_severity(line_str.lower())

            # Infer source
            source = f"Host Log ({filename})"
            if "sshd" in line_str:
                source = "Linux SSH Auth Daemon"
            elif "sudo" in line_str:
                source = "Linux Sudo Audit"
            elif "edr" in line_str.lower() or "powershell" in line_str.lower():
                source = "Endpoint EDR Agent"
            elif "firewall" in line_str.lower():
                source = "Network Firewall"
            elif "audit" in line_str.lower():
                source = "System Audit Trail"

            # Infer event type
            event_type = "System Activity"
            if "accepted password" in line_str.lower():
                event_type = "Successful Authentication"
            elif "failed" in line_str.lower() or "failure" in line_str.lower():
                event_type = "Authentication Failure / Alert"
            elif "process execution" in line_str.lower() or "spawn" in line_str.lower():
                event_type = "Process Execution"
            elif "lsass" in line_str.lower() or "mimikatz" in line_str.lower():
                event_type = "Credential Dumping / Memory Access"
            elif "smb" in line_str.lower():
                event_type = "Lateral SMB Connection"
            elif "upload" in line_str.lower() or "exfil" in line_str.lower():
                event_type = "Data Exfiltration"

            # Extract IP and process indicators
            details: Dict[str, Any] = {"raw_line_number": idx + 1}
            ips = IPV4_REGEX.findall(line_str)
            if ips:
                details["extracted_ips"] = ips

            logs.append({
                "id": f"EV-{file_id[:8]}-{idx+1:04d}",
                "evidence_file_id": file_id,
                "timestamp": timestamp,
                "source": source,
                "event_type": event_type,
                "severity": severity,
                "details": details,
                "raw_payload": line_str
            })

        return logs

    @staticmethod
    def _infer_severity(content_lower: str) -> str:
        """Heuristic severity scorer based on forensic threat indicators."""
        if any(term in content_lower for term in [
            'critical', 'mimikatz', 'exfiltration', 'lsass', 'unauthorized',
            'ransomware', 'cve-', 'c2 beacon', 'exploit', 'rootkit', 'malicious parent'
        ]):
            return "Critical"
        elif any(term in content_lower for term in [
            'high', 'powershell -enc', 'bypass', '445', 'smb', 'failure',
            'access denied', 'dump', 'multipartupload', 'putobject', 'spearphishing'
        ]):
            return "High"
        elif any(term in content_lower for term in [
            'medium', 'warn', 'warning', 'suspicious', 'download', 'stage2', 'temp'
        ]):
            return "Medium"
        elif any(term in content_lower for term in [
            'low', 'notice', 'allow', 'info'
        ]):
            return "Low"
        return "Info"
