import pytest
from services.hash_service import HashService

def test_hash_calculation_bytes():
    raw = b"Sample forensic payload for SHA-256 test."
    digest = HashService.calculate_sha256(raw)
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert digest == HashService.calculate_sha256(raw)

def test_hash_calculation_string():
    text = "User authentication failure event: admin from 192.168.1.100"
    digest = HashService.calculate_sha256(text)
    assert isinstance(digest, str)
    assert len(digest) == 64

def test_tamper_detection_property():
    original = b"Original log entry - integrity confirmed"
    tampered = b"Original log entry - integrity tampered!"
    h1 = HashService.calculate_sha256(original)
    h2 = HashService.calculate_sha256(tampered)
    assert h1 != h2

def test_process_log_entry_sealing():
    log = {
        "id": "TEST-01",
        "timestamp": "2026-08-01T12:00:00Z",
        "source": "Endpoint EDR",
        "event_type": "Process Launch",
        "severity": "High",
        "raw_payload": "Process powershell.exe spawned with arguments"
    }
    sealed = HashService.process_log_entry(log)
    assert "hash_sha256" in sealed
    assert sealed["hash_sha256"] is not None
    assert "VERIFIED" in sealed.get("chain_status")
