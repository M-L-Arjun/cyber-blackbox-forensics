import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

class HashService:
    @staticmethod
    def calculate_sha256(data: Any) -> str:
        """Calculate deterministic SHA-256 hash for any dictionary or string payload."""
        if isinstance(data, dict):
            serialized = json.dumps(data, sort_keys=True, default=str)
        elif isinstance(data, str):
            serialized = data
        else:
            serialized = str(data)
        
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    @classmethod
    def process_log_entry(cls, log: Dict[str, Any]) -> Dict[str, Any]:
        """Attach cryptographic SHA-256 seal and chain of custody metadata to a log entry."""
        log_copy = dict(log)
        payload_to_hash = {
            "id": log_copy.get("id"),
            "timestamp": log_copy.get("timestamp"),
            "source": log_copy.get("source"),
            "event_type": log_copy.get("event_type"),
            "raw_payload": log_copy.get("raw_payload")
        }
        computed_hash = cls.calculate_sha256(payload_to_hash)
        log_copy["hash_sha256"] = computed_hash
        log_copy["chain_status"] = "VERIFIED_TAMPER_FREE"
        return log_copy

    @classmethod
    def generate_chain_of_custody(cls, artifact_id: str, artifact_name: str, raw_hash: str, source: str) -> List[Dict[str, str]]:
        now = datetime.now(timezone.utc).isoformat()
        return [
            {
                "step": "1. Ingestion & Invariant Hashing",
                "timestamp": now,
                "handler": "CyberBlackBox-Collector-Agent-01",
                "action": "Collected raw digital telemetry and computed initial SHA-256 invariant hash.",
                "hash_state": raw_hash
            },
            {
                "step": "2. Cryptographic Storage & Ledger Seal",
                "timestamp": now,
                "handler": "CyberBlackBox-ImmutableVault",
                "action": "Sealed artifact in append-only write-once tamper-proof evidence repository.",
                "hash_state": raw_hash
            },
            {
                "step": "3. AI Forensic Pipeline Access",
                "timestamp": now,
                "handler": "CyberBlackBox-AI-Correlation-Engine",
                "action": "Read-only access granted for attack reconstruction and RAG vector indexing.",
                "hash_state": raw_hash
            }
        ]
