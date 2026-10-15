import pytest
from services.parser_service import ParserService, MAX_FILE_SIZE_BYTES

def test_parse_csv_evidence():
    csv_bytes = (
        b"timestamp,source,event_type,severity,source_ip,details\n"
        b"2026-08-01T10:00:00Z,Firewall,PortScan,High,203.0.113.50,SYN scan on port 445\n"
        b"2026-08-01T10:05:00Z,Auth,BruteForce,Critical,203.0.113.50,15 failed root attempts\n"
    )
    records, meta = ParserService.parse_file_bytes(csv_bytes, "firewall_logs.csv")
    assert len(records) == 2
    assert meta["record_count"] == 2
    assert meta["filename"] == "firewall_logs.csv"
    assert len(meta["sha256"]) == 64
    assert records[0]["event_type"] == "PortScan"
    assert records[1]["severity"] == "Critical"
    assert records[0]["hash_sha256"] is not None

def test_parse_json_evidence():
    json_bytes = b'''[
        {"timestamp": "2026-08-01T11:00:00Z", "source": "AWS CloudTrail", "event_type": "CreateUser", "severity": "Medium", "details": {"user": "attacker"}},
        {"timestamp": "2026-08-01T11:05:00Z", "source": "AWS CloudTrail", "event_type": "AttachAdminPolicy", "severity": "Critical", "details": {"user": "attacker"}}
    ]'''
    records, meta = ParserService.parse_file_bytes(json_bytes, "cloudtrail.json")
    assert len(records) == 2
    assert meta["record_count"] == 2
    assert records[0]["source"] == "AWS CloudTrail"
    assert records[1]["event_type"] == "AttachAdminPolicy"

def test_parse_jsonl_evidence():
    jsonl_bytes = (
        b'{"timestamp": "2026-08-01T12:00:00Z", "source": "EDR", "event_type": "ProcessExec", "severity": "High", "details": {"cmd": "whoami"}}\n'
        b'{"timestamp": "2026-08-01T12:02:00Z", "source": "EDR", "event_type": "NetworkConn", "severity": "Critical", "details": {"dst": "198.51.100.1"}}\n'
    )
    records, meta = ParserService.parse_file_bytes(jsonl_bytes, "edr_stream.jsonl")
    assert len(records) == 2
    assert records[0]["details"]["cmd"] == "whoami"

def test_parse_syslog_text_evidence():
    syslog_bytes = (
        b"Aug 01 13:00:00 server-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2\n"
        b"Aug 01 13:01:00 server-01 sudo: dev-user : TTY=pts/0 ; PWD=/home/dev-user ; USER=root ; COMMAND=/bin/bash\n"
    )
    records, meta = ParserService.parse_file_bytes(syslog_bytes, "auth.log")
    assert len(records) >= 2
    assert meta["record_count"] >= 2
    assert any("sshd" in r["raw_payload"] for r in records)

def test_empty_file_rejected():
    with pytest.raises(ValueError, match="empty"):
        ParserService.parse_file_bytes(b"", "empty.log")

def test_oversized_file_rejected():
    fake_huge = b"A" * (MAX_FILE_SIZE_BYTES + 1024)
    with pytest.raises(ValueError, match="maximum size limit"):
        ParserService.parse_file_bytes(fake_huge, "huge.log")

def test_latin1_encoding_resilience():
    latin1_bytes = "timestamp,source,event_type,severity,details\n2026-08-01T14:00:00Z,Firewall,AccentCaf\xe9,Low,Details with \xe9\xe8\xe0".encode("latin-1")
    records, meta = ParserService.parse_file_bytes(latin1_bytes, "latin.csv")
    assert len(records) == 1
    assert "AccentCaf" in records[0]["event_type"]
