from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class LogEntry(BaseModel):
    id: str
    timestamp: str
    source: str  # Endpoint, Firewall, AWS CloudTrail, Microsoft 365, Chrome, Active Directory, NIDS
    event_type: str
    severity: str  # Critical, High, Medium, Low, Info
    details: Dict[str, Any]
    raw_payload: str
    hash_sha256: Optional[str] = None
    chain_status: Optional[str] = "VERIFIED"

class EvidenceArtifact(BaseModel):
    id: str
    log_id: str
    artifact_name: str
    category: str
    sha256_hash: str
    timestamp: str
    source_system: str
    chain_of_custody: List[Dict[str, str]]
    verified: bool = True

class AttackGraphNode(BaseModel):
    id: str
    label: str
    type: str  # attacker, entrypoint, compromised_host, domain_controller, exfiltration_target
    status: str  # compromised, safe, suspicious
    ip: str
    details: str

class AttackGraphEdge(BaseModel):
    source: str
    target: str
    label: str
    protocol: str
    timestamp: str

class AttackGraph(BaseModel):
    nodes: List[AttackGraphNode]
    edges: List[AttackGraphEdge]

class TimelineStep(BaseModel):
    id: str
    time: str
    phase: str  # Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Exfiltration
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    summary: str
    description: str
    source: str
    evidence_ids: List[str]
    severity: str

class RAGQueryRequest(BaseModel):
    query: str
    incident_id: str = "INC-2026-8891"
    top_k: int = 4

class RetrievedChunk(BaseModel):
    id: str
    source_doc: str
    score: float
    content: str
    metadata: Dict[str, Any]

class RAGQueryResponse(BaseModel):
    query: str
    answer: str
    confidence: float
    retrieved_chunks: List[RetrievedChunk]
    mitre_references: List[str]
    suggested_followups: List[str]

class ResponseAction(BaseModel):
    id: str
    title: str
    target_system: str
    action_type: str  # ISOLATE_HOST, REVOKE_TOKEN, BLOCK_IP, PATCH_CVE, RESET_PASS
    risk_level: str  # High, Medium, Low
    status: str  # PENDING, EXECUTED, FAILED
    ai_rationale: str

class IncidentScenario(BaseModel):
    incident_id: str
    title: str
    summary: str
    threat_actor: str
    target_asset: str
    risk_score: int
    entry_point: str
    compromised_assets: List[str]
    logs: List[LogEntry]
    timeline: List[TimelineStep]
    graph: AttackGraph
    response_actions: List[ResponseAction]

class ForensicReport(BaseModel):
    report_id: str
    incident_id: str
    generated_at: str
    title: str
    executive_summary: str
    threat_actor_profile: str
    entry_vector: str
    compromised_assets: List[str]
    timeline_summary: List[Dict[str, str]]
    indicators_of_compromise: List[Dict[str, str]]
    chain_of_custody_seal: Dict[str, str]
    remediation_recommendations: List[str]
