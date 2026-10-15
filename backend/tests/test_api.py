import io
import pytest
from fastapi.testclient import TestClient
import main

@pytest.fixture
def client():
    # Trigger startup event to init db and seed baseline demo
    main.startup_event()
    return TestClient(main.app)

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["database"] == "SQLITE_ATTACHED"

def test_list_incidents(client):
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) >= 1
    assert any(i["incident_id"] == "INC-2026-8891" for i in incidents)

def test_get_incident_detail(client):
    res = client.get("/api/incidents/INC-2026-8891")
    assert res.status_code == 200
    inc = res.json()
    assert inc["incident_id"] == "INC-2026-8891"
    assert len(inc["logs"]) >= 5
    assert len(inc["timeline"]) >= 4
    assert len(inc["graph"]["nodes"]) >= 3

def test_get_incident_logs(client):
    res = client.get("/api/incidents/INC-2026-8891/logs")
    assert res.status_code == 200
    data = res.json()
    assert data["integrity_status"] == "ALL_HASHES_VERIFIED"
    assert len(data["master_evidence_hash"]) == 64
    assert len(data["logs"]) >= 5

def test_evidence_upload_and_pipeline(client):
    csv_content = (
        b"timestamp,source,event_type,severity,source_ip,details\n"
        b"2026-08-01T10:00:00Z,Firewall,PortScan,High,203.0.113.15,Inbound port scan\n"
        b"2026-08-01T10:05:00Z,Auth,BruteForce,Critical,203.0.113.15,Failed logins on SSH\n"
    )
    res = client.post(
        "/api/evidence/upload",
        files=[("files", ("firewall_test.csv", io.BytesIO(csv_content), "text/csv"))],
        data={"incident_title": "Automated Test Incident", "threat_actor": "TestActor"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    created_id = data["incident_id"]
    assert created_id.startswith("INC-")
    
    # Verify the created incident can be retrieved from DB
    detail_res = client.get(f"/api/incidents/{created_id}")
    assert detail_res.status_code == 200
    inc_detail = detail_res.json()
    assert inc_detail["title"] == "Automated Test Incident"
    assert inc_detail["threat_actor"] == "TestActor"
    assert len(inc_detail["logs"]) == 2

    # Verify RAG query on this incident
    rag_res = client.post(
        f"/api/incidents/{created_id}/rag",
        json={"query": "What IP is attacking us?"}
    )
    assert rag_res.status_code == 200
    rag_data = rag_res.json()
    assert len(rag_data["answer"]) > 20
    assert len(rag_data["suggested_followups"]) >= 1

    # Verify Report generation
    rep_res = client.get(f"/api/incidents/{created_id}/report")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["incident_id"] == created_id
    assert len(rep_data["chain_of_custody_seal"]["master_evidence_sha256"]) == 64

    # Verify Report download
    dl_res = client.get(f"/api/incidents/{created_id}/report/download")
    assert dl_res.status_code == 200
    assert "text/markdown" in dl_res.headers.get("content-type", "")
    assert created_id in dl_res.text

    # Verify deleting this uploaded incident succeeds
    del_res = client.delete(f"/api/incidents/{created_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "SUCCESS"

    # Verify it is no longer in DB
    del_check = client.get(f"/api/incidents/{created_id}")
    assert del_check.status_code == 404

def test_demo_deletion_protection(client):
    # Attempting to delete the demo incident should be forbidden
    res = client.delete("/api/incidents/INC-2026-8891")
    assert res.status_code == 400
    assert "Cannot delete" in res.json()["detail"]

def test_execute_response_action(client):
    res = client.post("/api/incidents/INC-2026-8891/actions/ACT-101/execute")
    assert res.status_code == 200
    data = res.json()
    assert data["action"]["status"] == "EXECUTED"
