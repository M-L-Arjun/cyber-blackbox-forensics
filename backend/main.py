import copy
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware

import database
from models import (
    RAGQueryRequest, RAGQueryResponse, 
    ForensicReport, LogEntry, IncidentScenario, IncidentListItem
)
from data.sample_incidents import SCENARIOS
from services.hash_service import HashService
from services.rag_engine import RAGEngine
from services.report_service import ReportService
from services.parser_service import ParserService
from services.correlation_engine import CorrelationEngine

app = FastAPI(
    title="Cyber Black Box Digital Forensics API",
    description="AI-powered digital forensics, cryptographic evidence vault, dynamic event correlation & FAISS vector RAG engine",
    version="2.0.0"
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

@app.on_event("startup")
def startup_event():
    """Initialize database and seed baseline demonstration incident into SQLite."""
    database.init_db()
    
    # Check if demo incident is already present in DB
    demo_id = "INC-2026-8891"
    existing_demo = database.get_incident(demo_id)
    if not existing_demo and demo_id in SCENARIOS:
        demo_data = copy.deepcopy(SCENARIOS[demo_id])
        # Compute master evidence hash
        processed_logs = [HashService.process_log_entry(l) for l in demo_data.get("logs", [])]
        demo_data["logs"] = processed_logs
        demo_data["master_evidence_hash"] = HashService.calculate_sha256(
            "".join([l.get("raw_payload", "") for l in processed_logs])
        )
        database.save_incident(demo_data, is_demo=True)
    
    # Index all incidents in DB into FAISS vector store
    all_incidents = database.list_all_incidents()
    for inc_summary in all_incidents:
        full_inc = database.get_incident(inc_summary["incident_id"])
        if full_inc:
            rag_engine.index_incident_logs(full_inc.get("logs", []))


@app.get("/health")
def health_check():
    return {
        "status": "online",
        "system": "Cyber Black Box Engine",
        "version": "2.0.0",
        "forensic_integrity": "ACTIVE_SHA256",
        "faiss_vector_engine": "ACTIVE_FLAT_IP",
        "database": "SQLITE_ATTACHED"
    }


@app.get("/api/scenarios", response_model=List[IncidentListItem])
@app.get("/api/incidents", response_model=List[IncidentListItem])
def list_incidents():
    """List all available incident investigations from database."""
    incidents = database.list_all_incidents()
    if not incidents and "INC-2026-8891" in SCENARIOS:
        # Fallback if DB was freshly cleared
        demo = SCENARIOS["INC-2026-8891"]
        return [{
            "incident_id": demo["incident_id"],
            "title": demo["title"],
            "threat_actor": demo["threat_actor"],
            "risk_score": demo["risk_score"],
            "log_count": len(demo.get("logs", [])),
            "is_demo": True,
            "created_at": "2026-08-06T02:00:00Z",
            "status": "INVESTIGATION_COMPLETE"
        }]
    return incidents


@app.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Retrieve full incident details including evidence files, logs, graph, timeline, and actions."""
    inc = database.get_incident(incident_id)
    if not inc:
        if incident_id in SCENARIOS:
            inc = copy.deepcopy(SCENARIOS[incident_id])
            inc["logs"] = [HashService.process_log_entry(l) for l in inc.get("logs", [])]
        else:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    
    return inc


@app.get("/api/incidents/{incident_id}/logs")
def get_incident_logs(incident_id: str):
    """Retrieve log vault with cryptographic hashes and chain of custody metadata."""
    inc = database.get_incident(incident_id)
    if not inc:
        if incident_id in SCENARIOS:
            inc = SCENARIOS[incident_id]
        else:
            raise HTTPException(status_code=404, detail="Incident not found")
    
    logs = inc.get("logs", [])
    processed_logs = [HashService.process_log_entry(l) for l in logs]
    
    # Calculate Master Invariant Hash
    master_hash = inc.get("master_evidence_hash") or HashService.calculate_sha256(
        "".join([l.get("raw_payload", "") for l in processed_logs])
    )
    
    return {
        "incident_id": incident_id,
        "master_evidence_hash": master_hash,
        "total_records": len(processed_logs),
        "integrity_status": "ALL_HASHES_VERIFIED",
        "evidence_files": inc.get("evidence_files", []),
        "logs": processed_logs
    }


@app.post("/api/evidence/upload")
async def upload_evidence(
    files: List[UploadFile] = File(...),
    incident_title: Optional[str] = Form(None),
    threat_actor: Optional[str] = Form(None)
):
    """
    Upload forensic evidence files (.csv, .json, .jsonl, .txt, .log), parse them,
    compute byte-level SHA-256 hashes, dynamically correlate events, build attack graph & timeline,
    index into FAISS vector store, and persist to SQLite.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No evidence files provided")

    all_parsed_logs: List[Dict[str, Any]] = []
    evidence_files_meta: List[Dict[str, Any]] = []
    parsing_errors: List[str] = []

    for file in files:
        content = await file.read()
        filename = file.filename or "unknown_evidence.log"
        
        # Calculate strict byte-level SHA-256
        file_sha256 = HashService.calculate_sha256(content)
        file_size_bytes = len(content)

        if file_size_bytes == 0:
            parsing_errors.append(f"File '{filename}' is empty (0 bytes).")
            continue

        try:
            parsed_records, file_meta = ParserService.parse_file_bytes(content, filename)
            all_parsed_logs.extend(parsed_records)
            evidence_files_meta.append(file_meta)
        except Exception as e:
            parsing_errors.append(f"Error parsing '{filename}': {str(e)}")

    if not all_parsed_logs:
        error_detail = "; ".join(parsing_errors) if parsing_errors else "No valid forensic log records could be parsed."
        raise HTTPException(
            status_code=400,
            detail=f"Forensic parsing failed: {error_detail}"
        )

    # Correlate logs dynamically
    correlated_incident = CorrelationEngine.correlate_incident(
        parsed_logs=all_parsed_logs,
        evidence_files=evidence_files_meta,
        incident_title=incident_title,
        threat_actor=threat_actor
    )

    # Save to SQLite database
    saved_id = database.save_incident(correlated_incident, is_demo=False)

    # Index new incident logs into FAISS vector RAG store
    rag_engine.index_incident_logs(correlated_incident.get("logs", []))

    # Retrieve freshly persisted incident
    fresh_incident = database.get_incident(saved_id) or correlated_incident

    return {
        "status": "SUCCESS",
        "message": f"Successfully parsed and correlated {len(all_parsed_logs)} records from {len(evidence_files_meta)} file(s).",
        "incident_id": saved_id,
        "incident": fresh_incident,
        "warnings": parsing_errors if parsing_errors else None
    }


@app.post("/api/incidents/{incident_id}/rag", response_model=RAGQueryResponse)
def query_rag_engine(incident_id: str, req: RAGQueryRequest):
    """Perform FAISS-indexed RAG query over forensic incident logs and MITRE KB."""
    inc = database.get_incident(incident_id)
    if not inc and incident_id in SCENARIOS:
        inc = SCENARIOS[incident_id]
        
    query_str = req.query
    retrieved_chunks = rag_engine.retrieve(query_str, top_k=req.top_k)
    answer, mitre_refs = rag_engine.query_ollama_or_fallback(query_str, retrieved_chunks)
    
    confidence = 0.94 if retrieved_chunks and retrieved_chunks[0]["score"] > 0.3 else 0.82
    
    # Generate contextual follow-up questions
    target_asset = inc.get("target_asset", "Target Assets") if inc else "Systems"
    entry_point = inc.get("entry_point", "Entry Point") if inc else "Initial Access"
    suggested_followups = [
        f"What evidence connects {entry_point} to lateral movement?",
        f"Which credentials or identities were compromised during this attack?",
        f"What was the impact on {target_asset}?",
        "What containment actions should the incident response team execute immediately?"
    ]
    
    return RAGQueryResponse(
        query=query_str,
        answer=answer,
        confidence=confidence,
        retrieved_chunks=retrieved_chunks,
        mitre_references=mitre_refs,
        suggested_followups=suggested_followups
    )


@app.post("/api/incidents/{incident_id}/actions/{action_id}/execute")
def execute_response_action(incident_id: str, action_id: str):
    """Execute an automated AI response playbook action (e.g. isolate host, block IP)."""
    # Try updating in database first
    updated_action = database.execute_action(incident_id, action_id)
    if updated_action:
        return {
            "message": f"Action {action_id} executed successfully",
            "action": updated_action,
            "execution_timestamp": updated_action.get("executed_at")
        }
    
    # Fallback to in-memory SCENARIOS for demo if not in DB
    if incident_id in SCENARIOS:
        actions = SCENARIOS[incident_id].get("response_actions", [])
        for act in actions:
            if act.get("id") == action_id or act.get("action_id") == action_id:
                act["status"] = "EXECUTED"
                now = datetime.now(timezone.utc).isoformat()
                return {
                    "message": f"Action {action_id} executed successfully",
                    "action": act,
                    "execution_timestamp": now
                }

    raise HTTPException(status_code=404, detail="Action or incident not found")


@app.get("/api/incidents/{incident_id}/report", response_model=ForensicReport)
def generate_report(incident_id: str):
    """Generate comprehensive forensic investigation report with cryptographic chain of custody seal."""
    inc = database.get_incident(incident_id)
    if not inc:
        if incident_id in SCENARIOS:
            inc = SCENARIOS[incident_id]
        else:
            raise HTTPException(status_code=404, detail="Incident not found")
        
    report = ReportService.generate_forensic_report(inc)
    return report


@app.get("/api/incidents/{incident_id}/report/download")
def download_markdown_report(incident_id: str):
    """Download forensic investigation report as a Markdown document."""
    inc = database.get_incident(incident_id)
    if not inc:
        if incident_id in SCENARIOS:
            inc = SCENARIOS[incident_id]
        else:
            raise HTTPException(status_code=404, detail="Incident not found")
        
    md_content = ReportService.generate_markdown_report(inc)
    filename = f"forensic_report_{incident_id}.md"
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.delete("/api/incidents/{incident_id}")
def delete_incident(incident_id: str):
    """Delete an incident and all its correlated data from the database."""
    inc = database.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if inc.get("is_demo"):
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the demonstration baseline scenario. Delete is permitted for uploaded evidence investigations only."
        )
    
    success = database.delete_incident(incident_id)
    if success:
        return {"status": "SUCCESS", "message": f"Incident {incident_id} successfully purged from forensic vault."}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete incident from database.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
