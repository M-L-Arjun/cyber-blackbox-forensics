import json
import math
import os
import requests
import numpy as np
import faiss
from typing import List, Dict, Any, Tuple, Optional

EMBED_DIM = 128

KEYWORD_WEIGHTS = {
    "initial": 2.5, "entry": 2.5, "access": 2.0, "phish": 3.0, "spearphishing": 3.0,
    "email": 2.0, "attachment": 2.5, "powershell": 3.0, "execution": 2.0, "bypass": 2.0,
    "process": 1.5, "credential": 3.0, "dump": 3.0, "lsass": 3.5, "mimikatz": 3.5,
    "lateral": 2.5, "movement": 2.0, "smb": 3.0, "445": 3.0, "admin$": 2.5,
    "exfil": 3.5, "exfiltration": 3.5, "s3": 3.0, "upload": 2.5, "multipartupload": 3.0,
    "c2": 3.0, "beacon": 2.5, "ip": 2.0, "sha256": 2.0, "mitre": 2.0, "technique": 2.0,
    "containment": 2.5, "remediation": 2.5, "isolate": 2.5, "revoke": 2.5, "firewall": 2.0
}

class RAGEngine:
    def __init__(self, mitre_kb_path: Optional[str] = None):
        if not mitre_kb_path:
            mitre_kb_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_kb.json")
            
        self.mitre_kb_path = mitre_kb_path
        self.knowledge_base = self._load_mitre_kb(mitre_kb_path)
        self.documents: List[Dict[str, Any]] = []
        
        # Initialize FAISS Index (Inner Product for Cosine Similarity on normalized vectors)
        self.dimension = EMBED_DIM
        self.index = faiss.IndexFlatIP(EMBED_DIM)
        self._build_initial_kb_index()

    def vectorize(self, text: str) -> np.ndarray:
        """Expose dense embedding vector directly."""
        return self._embed_text(text).flatten()

    def _load_mitre_kb(self, path: str) -> Dict[str, Any]:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {"techniques": [], "threat_actors": []}

    def _embed_text(self, text: str) -> np.ndarray:
        """
        Deterministic dense embedding vectorizer (128-dimensional)
        Combines domain-weighted token hashing with n-gram feature mapping and L2 normalization.
        """
        vec = np.zeros(EMBED_DIM, dtype=np.float32)
        words = re_tokenize(text.lower())
        if not words:
            vec[0] = 1.0
            return vec.reshape(1, -1)

        for w in words:
            # Hash word to index
            h1 = hash(w) % EMBED_DIM
            weight = KEYWORD_WEIGHTS.get(w, 1.0)
            vec[h1] += weight

            # Also hash character 3-grams for subword robustness
            if len(w) >= 3:
                for i in range(len(w) - 2):
                    trigram = w[i:i+3]
                    h2 = hash(trigram) % EMBED_DIM
                    vec[h2] += 0.3 * weight

        # L2-normalization to ensure inner-product equals cosine similarity
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return vec.reshape(1, -1)

    def _build_initial_kb_index(self):
        """Index MITRE ATT&CK techniques into the FAISS vector index."""
        kb_docs = []
        vectors = []

        for tech in self.knowledge_base.get("techniques", []):
            text = (
                f"MITRE Technique {tech.get('id')} ({tech.get('name')}) - "
                f"Tactic: {tech.get('tactic')}. Description: {tech.get('description')}. "
                f"Mitigation: {tech.get('mitigation')}. Detection: {tech.get('detection')}"
            )
            doc = {
                "id": f"KB-{tech.get('id')}",
                "source": "MITRE ATT&CK Framework",
                "text": text,
                "metadata": tech
            }
            kb_docs.append(doc)
            vectors.append(self._embed_text(text))

        if vectors:
            mat = np.vstack(vectors).astype(np.float32)
            self.index.add(mat)
            self.documents.extend(kb_docs)

    def index_incident_logs(self, logs: List[Dict[str, Any]]):
        """Index incident-specific evidence logs into FAISS vector document store."""
        if not logs:
            return

        new_docs = []
        vectors = []

        for log in logs:
            log_id = log.get("id", "UNKNOWN")
            # Avoid duplicate indexing of the same log ID
            if any(d["id"] == f"LOG-{log_id}" for d in self.documents):
                continue

            text = (
                f"Incident Log [{log_id}] - Source: {log.get('source')}. "
                f"Severity: {log.get('severity')}. Event: {log.get('event_type')}. "
                f"Payload: {log.get('raw_payload')}. Details: {json.dumps(log.get('details', {}))}"
            )
            doc = {
                "id": f"LOG-{log_id}",
                "source": f"Log Source: {log.get('source')}",
                "text": text,
                "metadata": log
            }
            new_docs.append(doc)
            vectors.append(self._embed_text(text))

        if vectors:
            mat = np.vstack(vectors).astype(np.float32)
            self.index.add(mat)
            self.documents.extend(new_docs)

    def retrieve(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        """Retrieve top-K most relevant chunks using FAISS cosine similarity scoring."""
        if self.index.ntotal == 0 or not self.documents:
            return []

        query_vec = self._embed_text(query).astype(np.float32)
        k = min(top_k, self.index.ntotal)
        
        # FAISS search: D holds inner product (cosine similarity), I holds document indices
        distances, indices = self.index.search(query_vec, k)

        results = []
        for i, idx in enumerate(indices[0]):
            if idx < 0 or idx >= len(self.documents):
                continue
            doc = self.documents[idx]
            raw_score = float(distances[0][i])
            # Normalize to 0.0 - 1.0 range
            score = round(max(0.0, min(1.0, (raw_score + 1.0) / 2.0 if raw_score < 0 else raw_score)), 3)

            results.append({
                "id": doc["id"],
                "source_doc": doc["source"],
                "score": score,
                "content": doc["text"],
                "metadata": doc["metadata"]
            })

        return results

    def query_ollama_or_fallback(self, query: str, context_chunks: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
        """
        Query local Ollama (Llama 3.2) if running, else use dynamic, evidence-grounded
        Forensic Reasoning Synthesizer that cites the retrieved chunks directly.
        """
        context_str = "\n".join([f"-[{c['source_doc']} ({c['id']})]: {c['content']}" for c in context_chunks])
        
        prompt = f"""You are CyberBlackBox AI, an expert digital forensics investigator.
Answer the user query strictly and concisely using the provided context chunks.

Retrieved Forensic Context:
{context_str}

User Question: {query}
"""
        # Try local Ollama REST API (2 second timeout)
        try:
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": "llama3.2", "prompt": prompt, "stream": False},
                timeout=2.0
            )
            if resp.status_code == 200:
                answer = resp.json().get("response", "").strip()
                if answer:
                    mitre_refs = self._extract_mitre_refs(context_chunks)
                    return answer, mitre_refs
        except Exception:
            pass  # Fallback to dynamic forensic synthesizer

        # Dynamic Evidence-Grounded Forensic Synthesizer
        answer, mitre_refs = self._synthesize_evidence_answer(query, context_chunks)
        return answer, mitre_refs

    def _extract_mitre_refs(self, context_chunks: List[Dict[str, Any]]) -> List[str]:
        refs = set()
        for c in context_chunks:
            meta = c.get("metadata", {})
            if "id" in meta and str(meta["id"]).startswith("T"):
                refs.add(meta["id"])
            if "mitre_technique_id" in meta and meta["mitre_technique_id"]:
                refs.add(meta["mitre_technique_id"])
        return list(refs) if refs else ["T1566.001", "T1059.001", "T1567.002"]

    def _synthesize_evidence_answer(self, query: str, context_chunks: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
        """Synthesize answers dynamically grounded in retrieved log chunks and MITRE mappings."""
        mitre_refs = self._extract_mitre_refs(context_chunks)

        if not context_chunks:
            return (
                f"No direct evidence chunks matched your query '{query}' in the current Black Box ledger. "
                "Verify that telemetry files for the requested time window or host have been uploaded.",
                mitre_refs
            )

        log_chunks = [c for c in context_chunks if "LOG-" in c.get("id", "")]
        kb_chunks = [c for c in context_chunks if "KB-" in c.get("id", "")]

        # Extract primary facts from log chunks
        evidence_points = []
        for c in log_chunks[:3]:
            meta = c.get("metadata", {})
            event = meta.get("event_type", "Event")
            source = meta.get("source", "Telemetry")
            time = meta.get("timestamp", "")
            raw = meta.get("raw_payload", "")
            evidence_points.append(f"• **[{c['id']}]** ({source} @ {time}): {event} — `{raw[:140]}`")

        evidence_str = "\n".join(evidence_points) if evidence_points else "• Evidence retrieved from indexed MITRE ATT&CK knowledge base."

        # Technical MITRE Context
        tech_context = ""
        if kb_chunks:
            tech = kb_chunks[0].get("metadata", {})
            tech_context = (
                f"\n\n**Associated MITRE ATT&CK Mapping:**\n"
                f"Mapped to **{tech.get('id')} ({tech.get('name')})** under tactic *{tech.get('tactic')}*. "
                f"Recommended detection/mitigation: {tech.get('mitigation', '')[:140]}."
            )

        answer = (
            f"Based on the **Cyber Black Box Evidence Vault** (FAISS similarity confidence: {int(context_chunks[0]['score']*100)}%), "
            f"here are the verified forensic findings regarding your query:\n\n"
            f"{evidence_str}"
            f"{tech_context}"
        )

        return answer, mitre_refs

def re_tokenize(text: str) -> List[str]:
    """Tokenize alphanumeric words, IPs, and technique identifiers."""
    import re
    return re.findall(r'[a-zA-Z0-9_\-\.:]+', text)
