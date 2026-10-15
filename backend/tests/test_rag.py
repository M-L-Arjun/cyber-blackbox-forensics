import pytest
import numpy as np
from services.rag_engine import RAGEngine

def test_rag_engine_initialization():
    engine = RAGEngine()
    assert engine.index is not None
    assert engine.index.ntotal >= 6  # At least MITRE KB techniques indexed
    assert engine.dimension == 128

def test_vector_normalization():
    engine = RAGEngine()
    vec = engine.vectorize("powershell lsass credential dumping")
    norm = np.linalg.norm(vec)
    assert pytest.approx(norm, 0.001) == 1.0

def test_rag_retrieval():
    engine = RAGEngine()
    results = engine.retrieve("credential dumping LSASS mimikatz", top_k=3)
    assert len(results) > 0
    top_chunk = results[0]
    assert "score" in top_chunk
    assert "content" in top_chunk
    assert "id" in top_chunk
    # Check that T1003 is retrieved
    assert any("T1003" in r["content"] for r in results)

def test_rag_query_fallback():
    engine = RAGEngine()
    retrieved = engine.retrieve("spearphishing attachment", top_k=2)
    answer, mitre_refs = engine.query_ollama_or_fallback("How did initial access occur?", retrieved)
    assert isinstance(answer, str)
    assert len(answer) > 50
    assert "Cyber Black Box Evidence Vault" in answer or "T1566" in answer
    assert isinstance(mitre_refs, list)
