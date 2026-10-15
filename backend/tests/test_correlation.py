import pytest
from services.correlation_engine import CorrelationEngine

def test_chronological_sorting():
    logs = [
        {"id": "L3", "timestamp": "2026-08-01T15:00:00Z", "raw_payload": "Third"},
        {"id": "L1", "timestamp": "2026-08-01T10:00:00Z", "raw_payload": "First"},
        {"id": "L2", "timestamp": "2026-08-01T12:00:00Z", "raw_payload": "Second"},
    ]
    sorted_logs = CorrelationEngine._sort_logs_chronologically(logs)
    assert [l["id"] for l in sorted_logs] == ["L1", "L2", "L3"]

def test_entity_extraction():
    logs = [
        {
            "id": "L1",
            "timestamp": "2026-08-01T10:00:00Z",
            "raw_payload": "Inbound connection from 198.51.100.99 to 10.0.4.12 workstation DEV-WS-01",
            "details": {"user": "alice", "source_ip": "198.51.100.99", "dest_ip": "10.0.4.12", "host": "DEV-WS-01"}
        }
    ]
    extracted = CorrelationEngine._extract_entities(logs)
    assert "198.51.100.99" in extracted["external_ips"]
    assert "10.0.4.12" in extracted["internal_ips"]
    assert "DEV-WS-01" in extracted["hosts"]
    assert "alice" in extracted["users"]

def test_mitre_attack_mapping():
    logs = [
        {
            "id": "L1",
            "timestamp": "2026-08-01T10:00:00Z",
            "event_type": "Spearphishing Email Delivered",
            "severity": "High",
            "raw_payload": "Email with attachment malicious.pdf.exe",
            "details": {}
        },
        {
            "id": "L2",
            "timestamp": "2026-08-01T10:05:00Z",
            "event_type": "Process Execution",
            "severity": "Critical",
            "raw_payload": "powershell.exe -ExecutionPolicy Bypass -Enc ABC",
            "details": {}
        }
    ]
    extracted = CorrelationEngine._extract_entities(logs)
    timeline = CorrelationEngine._generate_timeline(logs, extracted)
    assert len(timeline) == 2
    assert timeline[0]["mitre_technique_id"] == "T1566.001"
    assert timeline[1]["mitre_technique_id"] == "T1059.001"

def test_dynamic_attack_graph_synthesis():
    logs = [
        {
            "id": "L1",
            "timestamp": "2026-08-01T10:00:00Z",
            "raw_payload": "Connection from 198.51.100.4 to 10.0.4.12 DEV-WS-04",
            "details": {"source_ip": "198.51.100.4", "dest_ip": "10.0.4.12", "host": "DEV-WS-04"}
        }
    ]
    extracted = CorrelationEngine._extract_entities(logs)
    timeline = CorrelationEngine._generate_timeline(logs, extracted)
    graph = CorrelationEngine._generate_attack_graph(logs, extracted, timeline)
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1

def test_correlate_incident_full_pipeline():
    logs = [
        {
            "id": "L1",
            "timestamp": "2026-08-01T10:00:00Z",
            "source": "M365",
            "event_type": "Spearphishing Email",
            "severity": "High",
            "raw_payload": "Malicious attachment invoice.pdf.exe",
            "details": {"user": "bob"}
        },
        {
            "id": "L2",
            "timestamp": "2026-08-01T10:10:00Z",
            "source": "EDR",
            "event_type": "Credential Dump",
            "severity": "Critical",
            "raw_payload": "mimikatz lsass dump on host DEV-WS-02",
            "details": {"host": "DEV-WS-02"}
        }
    ]
    evidence_meta = [{"filename": "sample.csv", "sha256": "abc12345", "record_count": 2}]
    res = CorrelationEngine.correlate_incident(logs, evidence_meta, "Test Breach", "ThreatGroupX")
    assert res["title"] == "Test Breach"
    assert res["threat_actor"] == "ThreatGroupX"
    assert res["risk_score"] >= 65
    assert len(res["timeline"]) == 2
    assert len(res["response_actions"]) >= 1
    assert res["incident_id"].startswith("INC-")
