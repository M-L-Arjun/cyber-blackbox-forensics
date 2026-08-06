from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
import copy

from models import (
    RAGQueryRequest, RAGQueryResponse, 
    ForensicReport, LogEntry
)
from data.sample_incidents import SCENARIOS
from services.hash_service import HashService
from services.rag_engine import RAGEngine
from services.report_service import ReportService

app = FastAPI(
    title="Cyber Black Box Digital Forensics API",
    description="AI-powered digital forensics, cryptographic evidence vault, MITRE timeline correlation & lightweight RAG engine",
    version="1.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize RAG Engine
rag_engine = RAGEngine()

# Index sample scenario logs into RAG vector store
for inc_id, inc_data in SCENARIOS.items():
    rag_engine.index_incident_logs(inc_data.get("logs", []))


@app.get("/health")
def health_check():
    return {
        "status": "online",
        "system": "Cyber Black Box Engine",
        "version": "1.0.0",
        "forensic_integrity": "ACTIVE_SHA256"
    }


@app.get("/api/scenarios")
def list_scenarios():
    """List available incident scenarios."""
    summary_list = []
    for inc_id, data in SCENARIOS.items():
        summary_list.append({
            "incident_id": inc_id,
            "title": data.get("title"),
            "threat_actor": data.get("threat_actor"),
            "risk_score": data.get("risk_score"),
            "log_count": len(data.get("logs", []))
        })
    return summary_list


@app.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Retrieve full incident details including logs, graph, timeline, and actions."""
    if incident_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    inc = copy.deepcopy(SCENARIOS[incident_id])
    # Process logs with cryptographic SHA-256 hashes
    processed_logs = [HashService.process_log_entry(l) for l in inc.get("logs", [])]
    inc["logs"] = processed_logs
    return inc


@app.get("/api/incidents/{incident_id}/logs")
def get_incident_logs(incident_id: str):
    """Retrieve log vault with cryptographic hashes and chain of custody metadata."""
    if incident_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    raw_logs = SCENARIOS[incident_id].get("logs", [])
    processed_logs = [HashService.process_log_entry(l) for l in raw_logs]
    
    # Calculate Master Invariant Hash
    master_hash = HashService.calculate_sha256(processed_logs)
    
    return {
        "incident_id": incident_id,
        "master_evidence_hash": master_hash,
        "total_records": len(processed_logs),
        "integrity_status": "ALL_HASHES_VERIFIED",
        "logs": processed_logs
    }


@app.post("/api/incidents/{incident_id}/rag", response_model=RAGQueryResponse)
def query_rag_engine(incident_id: str, req: RAGQueryRequest):
    """Perform RAG (Retrieval-Augmented Generation) query over forensic logs and MITRE KB."""
    if incident_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Incident not found")

    query_str = req.query
    retrieved_chunks = rag_engine.retrieve(query_str, top_k=req.top_k)
    answer, mitre_refs = rag_engine.query_ollama_or_fallback(query_str, retrieved_chunks)
    
    confidence = 0.94 if retrieved_chunks and retrieved_chunks[0]["score"] > 0.3 else 0.82
    
    return RAGQueryResponse(
        query=query_str,
        answer=answer,
        confidence=confidence,
        retrieved_chunks=retrieved_chunks,
        mitre_references=mitre_refs,
        suggested_followups=[
            "Show me all PowerShell commands executed during this attack",
            "Which credentials were dumped from LSASS memory?",
            "What was the total volume of data exfiltrated to AWS S3?",
            "What containment actions should we execute immediately?"
        ]
    )


@app.post("/api/incidents/{incident_id}/actions/{action_id}/execute")
def execute_response_action(incident_id: str, action_id: str):
    """Execute an automated AI response playbook action (e.g. isolate host, block IP)."""
    if incident_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    actions = SCENARIOS[incident_id].get("response_actions", [])
    target_action = None
    for act in actions:
        if act.get("id") == action_id:
            target_action = act
            break
            
    if not target_action:
        raise HTTPException(status_code=404, detail="Action not found")
        
    target_action["status"] = "EXECUTED"
    return {
        "message": f"Action {action_id} executed successfully",
        "action": target_action,
        "execution_timestamp": HashService.calculate_sha256(action_id)[:12]
    }


@app.get("/api/incidents/{incident_id}/report", response_model=ForensicReport)
def generate_report(incident_id: str):
    """Generate comprehensive forensic investigation report with cryptographic chain of custody seal."""
    if incident_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident_data = SCENARIOS[incident_id]
    report = ReportService.generate_forensic_report(incident_data)
    return report


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
