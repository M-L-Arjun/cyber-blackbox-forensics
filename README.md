# 🛡️ Cyber Black Box for Digital Forensics

An AI-powered digital forensics & incident response platform featuring continuous multi-source evidence collection, cryptographic **SHA-256 invariant seals**, automated **MITRE ATT&CK topology reconstruction**, and a **RAG (Retrieval-Augmented Generation)** vector search engine.

---

## 🌟 Key Features

- **🛡️ Cryptographic Evidence Vault**: Continuous ingestion of endpoint logs, network traffic, EDR alerts, and cloud audit logs with immutable SHA-256 invariant hash seals.
- **🤖 RAG AI Forensic Assistant**: Ask natural language questions ("How did the attacker enter?") powered by Sentence-Transformers vector embeddings and FAISS / Cosine similarity matching.
- **📊 MITRE ATT&CK Topology Graph**: Visual reconstruction of entry vectors, credential dumping, lateral movement, and exfiltration targets.
- **📈 Side-by-Side Comparative Benchmark**: Benchmark comparing traditional manual investigation (21 Days MTTR) against the Cyber Black Box (3 Mins MTTR).
- **📋 Automated Containment Playbooks**: 1-click execution simulation for isolating compromised hosts and revoking access keys.
- **📄 Printable Forensic Reports**: Generate court-ready investigation reports with cryptographic chain-of-custody verification seals.

---

## ⚙️ Tech Stack

### Frontend
- **React.js** + **Vite**
- **Tailwind CSS** (Custom Warm Cream & Crimson Red Forensic Theme)
- **Recharts** (Threat Escalation Curve & Benchmark Charts)
- **Lucide React** (Security Icons)
- **Axios** (REST API Client)

### Backend
- **Python 3.11** + **FastAPI** + **Uvicorn**
- **Pydantic** (Data Schemas)
- **Sentence-Transformers** + **FAISS / Vector Similarity Engine**
- **MITRE ATT&CK Knowledge Base Integration**

---

## 🚀 Quick Start

### 1. Backend Server
```bash
cd backend
pip install -r requirements.txt
python main.py
```
*Backend runs on `http://127.0.0.1:8080`*

### 2. Frontend Application
```bash
cd frontend
npm install
npm run dev
```
*Frontend runs on `http://localhost:3000`*
