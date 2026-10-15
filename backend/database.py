import sqlite3
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_blackbox.db")

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables with schema migrations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Incidents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        threat_actor TEXT,
        target_asset TEXT,
        risk_score INTEGER DEFAULT 50,
        entry_point TEXT,
        compromised_assets TEXT, -- JSON array
        is_demo INTEGER DEFAULT 0,
        master_evidence_hash TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Evidence files table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence_files (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_sha256 TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        content_type TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    # Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        evidence_file_id TEXT,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        raw_payload TEXT NOT NULL,
        details_json TEXT, -- JSON dictionary
        hash_sha256 TEXT NOT NULL,
        chain_status TEXT DEFAULT 'VERIFIED',
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    # Timeline steps table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS timeline_steps (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        step_order INTEGER NOT NULL,
        time TEXT NOT NULL,
        phase TEXT NOT NULL,
        mitre_tactic TEXT,
        mitre_technique_id TEXT,
        mitre_technique_name TEXT,
        summary TEXT NOT NULL,
        description TEXT NOT NULL,
        source TEXT NOT NULL,
        evidence_ids TEXT, -- JSON array
        severity TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    # Attack graph nodes table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS graph_nodes (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        label TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        ip TEXT NOT NULL,
        details TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    # Attack graph edges table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS graph_edges (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        label TEXT NOT NULL,
        protocol TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    # Response actions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS response_actions (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_id TEXT NOT NULL,
        title TEXT NOT NULL,
        target_system TEXT NOT NULL,
        action_type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        status TEXT NOT NULL,
        ai_rationale TEXT NOT NULL,
        executed_at TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()

def save_incident(incident_data: Dict[str, Any], is_demo: bool = False):
    """Save or update an incident and all associated children."""
    conn = get_db_connection()
    cursor = conn.cursor()

    inc_id = incident_data["incident_id"]
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
    INSERT INTO incidents (
        incident_id, title, summary, threat_actor, target_asset,
        risk_score, entry_point, compromised_assets, is_demo,
        master_evidence_hash, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(incident_id) DO UPDATE SET
        title = excluded.title,
        summary = excluded.summary,
        threat_actor = excluded.threat_actor,
        target_asset = excluded.target_asset,
        risk_score = excluded.risk_score,
        entry_point = excluded.entry_point,
        compromised_assets = excluded.compromised_assets,
        master_evidence_hash = excluded.master_evidence_hash
    """, (
        inc_id,
        incident_data.get("title", "Untitled Incident"),
        incident_data.get("summary", ""),
        incident_data.get("threat_actor", "Unknown Adversary"),
        incident_data.get("target_asset", "Unknown"),
        incident_data.get("risk_score", 50),
        incident_data.get("entry_point", "Unknown"),
        json.dumps(incident_data.get("compromised_assets", [])),
        1 if is_demo else 0,
        incident_data.get("master_evidence_hash", ""),
        incident_data.get("created_at", now)
    ))

    # Save logs
    cursor.execute("DELETE FROM logs WHERE incident_id = ?", (inc_id,))
    for idx, log in enumerate(incident_data.get("logs", [])):
        orig_id = log.get("id") or f"LOG-{idx+1:03d}"
        scoped_log_id = f"{inc_id}-{orig_id}"
        cursor.execute("""
        INSERT INTO logs (
            id, incident_id, evidence_file_id, timestamp, source,
            event_type, severity, raw_payload, details_json, hash_sha256, chain_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp = excluded.timestamp,
            source = excluded.source,
            event_type = excluded.event_type,
            severity = excluded.severity,
            raw_payload = excluded.raw_payload,
            details_json = excluded.details_json,
            hash_sha256 = excluded.hash_sha256,
            chain_status = excluded.chain_status
        """, (
            scoped_log_id,
            inc_id,
            log.get("evidence_file_id"),
            log.get("timestamp", now),
            log.get("source", "Unknown"),
            log.get("event_type", "General Event"),
            log.get("severity", "Medium"),
            log.get("raw_payload", ""),
            json.dumps(log.get("details", {})),
            log.get("hash_sha256", ""),
            log.get("chain_status", "VERIFIED")
        ))

    # Save timeline
    cursor.execute("DELETE FROM timeline_steps WHERE incident_id = ?", (inc_id,))
    for idx, step in enumerate(incident_data.get("timeline", [])):
        orig_step_id = step.get("id") or f"TL-{idx+1}"
        scoped_step_id = f"{inc_id}-{orig_step_id}"
        cursor.execute("""
        INSERT INTO timeline_steps (
            id, incident_id, step_order, time, phase, mitre_tactic,
            mitre_technique_id, mitre_technique_name, summary,
            description, source, evidence_ids, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scoped_step_id,
            inc_id,
            idx + 1,
            step.get("time", ""),
            step.get("phase", "General"),
            step.get("mitre_tactic", ""),
            step.get("mitre_technique_id", ""),
            step.get("mitre_technique_name", ""),
            step.get("summary", ""),
            step.get("description", ""),
            step.get("source", ""),
            json.dumps(step.get("evidence_ids", [])),
            step.get("severity", "Medium")
        ))

    # Save graph nodes
    cursor.execute("DELETE FROM graph_nodes WHERE incident_id = ?", (inc_id,))
    graph = incident_data.get("graph", {})
    for node in graph.get("nodes", []):
        cursor.execute("""
        INSERT INTO graph_nodes (
            id, incident_id, node_id, label, type, status, ip, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"{inc_id}-{node['id']}",
            inc_id,
            node["id"],
            node.get("label", ""),
            node.get("type", "server"),
            node.get("status", "safe"),
            node.get("ip", ""),
            node.get("details", "")
        ))

    # Save graph edges
    cursor.execute("DELETE FROM graph_edges WHERE incident_id = ?", (inc_id,))
    for idx, edge in enumerate(graph.get("edges", [])):
        cursor.execute("""
        INSERT INTO graph_edges (
            id, incident_id, source, target, label, protocol, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            f"{inc_id}-edge-{idx+1}",
            inc_id,
            edge.get("source", ""),
            edge.get("target", ""),
            edge.get("label", ""),
            edge.get("protocol", "TCP"),
            edge.get("timestamp", "")
        ))

    # Save response actions
    cursor.execute("DELETE FROM response_actions WHERE incident_id = ?", (inc_id,))
    for action in incident_data.get("response_actions", []):
        cursor.execute("""
        INSERT INTO response_actions (
            id, incident_id, action_id, title, target_system,
            action_type, risk_level, status, ai_rationale
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"{inc_id}-{action['id']}",
            inc_id,
            action["id"],
            action.get("title", ""),
            action.get("target_system", ""),
            action.get("action_type", "GENERAL"),
            action.get("risk_level", "Medium"),
            action.get("status", "PENDING"),
            action.get("ai_rationale", "")
        ))

    conn.commit()
    conn.close()
    return inc_id

def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full incident dictionary from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    inc_row = cursor.fetchone()
    if not inc_row:
        conn.close()
        return None

    # Load logs
    cursor.execute("SELECT * FROM logs WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,))
    log_rows = cursor.fetchall()
    logs = []
    for l in log_rows:
        lid = l["id"]
        if lid.startswith(f"{incident_id}-"):
            lid = lid[len(incident_id) + 1:]
        logs.append({
            "id": lid,
            "timestamp": l["timestamp"],
            "source": l["source"],
            "event_type": l["event_type"],
            "severity": l["severity"],
            "details": json.loads(l["details_json"] or "{}"),
            "raw_payload": l["raw_payload"],
            "hash_sha256": l["hash_sha256"],
            "chain_status": l["chain_status"]
        })

    # Load timeline
    cursor.execute("SELECT * FROM timeline_steps WHERE incident_id = ? ORDER BY step_order ASC", (incident_id,))
    tl_rows = cursor.fetchall()
    timeline = []
    for t in tl_rows:
        tid = t["id"]
        if tid.startswith(f"{incident_id}-"):
            tid = tid[len(incident_id) + 1:]
        timeline.append({
            "id": tid,
            "time": t["time"],
            "phase": t["phase"],
            "mitre_tactic": t["mitre_tactic"] or "",
            "mitre_technique_id": t["mitre_technique_id"] or "",
            "mitre_technique_name": t["mitre_technique_name"] or "",
            "summary": t["summary"],
            "description": t["description"],
            "source": t["source"],
            "evidence_ids": json.loads(t["evidence_ids"] or "[]"),
            "severity": t["severity"]
        })

    # Load graph nodes
    cursor.execute("SELECT * FROM graph_nodes WHERE incident_id = ?", (incident_id,))
    node_rows = cursor.fetchall()
    nodes = [{
        "id": n["node_id"],
        "label": n["label"],
        "type": n["type"],
        "status": n["status"],
        "ip": n["ip"],
        "details": n["details"]
    } for n in node_rows]

    # Load graph edges
    cursor.execute("SELECT * FROM graph_edges WHERE incident_id = ?", (incident_id,))
    edge_rows = cursor.fetchall()
    edges = [{
        "source": e["source"],
        "target": e["target"],
        "label": e["label"],
        "protocol": e["protocol"],
        "timestamp": e["timestamp"]
    } for e in edge_rows]

    # Load response actions
    cursor.execute("SELECT * FROM response_actions WHERE incident_id = ?", (incident_id,))
    act_rows = cursor.fetchall()
    actions = [{
        "id": a["action_id"],
        "title": a["title"],
        "target_system": a["target_system"],
        "action_type": a["action_type"],
        "risk_level": a["risk_level"],
        "status": a["status"],
        "ai_rationale": a["ai_rationale"]
    } for a in act_rows]

    # Load evidence files
    cursor.execute("SELECT * FROM evidence_files WHERE incident_id = ?", (incident_id,))
    file_rows = cursor.fetchall()
    files = [{
        "id": f["id"],
        "filename": f["filename"],
        "file_sha256": f["file_sha256"],
        "file_size_bytes": f["file_size_bytes"],
        "content_type": f["content_type"],
        "uploaded_at": f["uploaded_at"]
    } for f in file_rows]

    conn.close()

    return {
        "incident_id": inc_row["incident_id"],
        "title": inc_row["title"],
        "summary": inc_row["summary"],
        "threat_actor": inc_row["threat_actor"],
        "target_asset": inc_row["target_asset"],
        "risk_score": inc_row["risk_score"],
        "entry_point": inc_row["entry_point"],
        "compromised_assets": json.loads(inc_row["compromised_assets"] or "[]"),
        "is_demo": bool(inc_row["is_demo"]),
        "master_evidence_hash": inc_row["master_evidence_hash"],
        "created_at": inc_row["created_at"],
        "evidence_files": files,
        "logs": logs,
        "timeline": timeline,
        "graph": {"nodes": nodes, "edges": edges},
        "response_actions": actions
    }

def list_all_incidents() -> List[Dict[str, Any]]:
    """List summary for all incidents."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT incident_id, title, threat_actor, risk_score, is_demo, created_at,
           (SELECT COUNT(*) FROM logs WHERE logs.incident_id = incidents.incident_id) as log_count
    FROM incidents
    ORDER BY is_demo ASC, created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "incident_id": r["incident_id"],
        "title": r["title"],
        "threat_actor": r["threat_actor"],
        "risk_score": r["risk_score"],
        "is_demo": bool(r["is_demo"]),
        "log_count": r["log_count"],
        "created_at": r["created_at"]
    } for r in rows]

def execute_action(incident_id: str, action_id: str) -> Optional[Dict[str, Any]]:
    """Mark an action as executed in the database and return updated action record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    UPDATE response_actions
    SET status = 'EXECUTED', executed_at = ?
    WHERE incident_id = ? AND action_id = ?
    """, (now, incident_id, action_id))
    success = cursor.rowcount > 0
    conn.commit()
    
    action = None
    if success:
        cursor.execute("SELECT * FROM response_actions WHERE incident_id = ? AND action_id = ?", (incident_id, action_id))
        row = cursor.fetchone()
        if row:
            action = {
                "id": row["action_id"],
                "action_id": row["action_id"],
                "title": row["title"],
                "target_system": row["target_system"],
                "action_type": row["action_type"],
                "risk_level": row["risk_level"],
                "status": row["status"],
                "ai_rationale": row["ai_rationale"],
                "executed_at": row["executed_at"]
            }
    conn.close()
    return action

def delete_incident(incident_id: str) -> bool:
    """Delete an incident and all associated children."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM evidence_files WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM logs WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM timeline_steps WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM graph_nodes WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM graph_edges WHERE incident_id = ?", (incident_id,))
    cursor.execute("DELETE FROM response_actions WHERE incident_id = ?", (incident_id,))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success
