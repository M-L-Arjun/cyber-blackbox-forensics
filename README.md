# 🛡️ Cyber Black Box for Digital Forensics v2.0

An AI-powered digital forensics and cyberattack reconstruction platform featuring multi-source evidence parsing, cryptographic **SHA-256 invariant seals**, dynamic **MITRE ATT&CK attack graph reconstruction**, an offline **FAISS dense vector RAG engine**, and **SQLite database persistence**.

---

## 🌐 Run & Test Anywhere (Instant Cloud Links)

| Platform | Type | Link / Action |
|---|---|---|
| **GitHub Codespaces** | **Full Stack Cloud IDE** (Backend + Frontend) | [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/M-L-Arjun/cyber-blackbox-forensics) |
| **Vercel** | **1-Click Frontend Cloud Deploy** | [![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/M-L-Arjun/cyber-blackbox-forensics) |
| **Render** | **1-Click Backend Cloud Deploy** | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/M-L-Arjun/cyber-blackbox-forensics) |
| **GitHub Pages** | **Live Hosted Frontend** | [https://m-l-arjun.github.io/cyber-blackbox-forensics/](https://m-l-arjun.github.io/cyber-blackbox-forensics/) |

> **Tip:** You can launch a complete running instance inside your web browser right now with zero installation using the **[Open in GitHub Codespaces](https://codespaces.new/M-L-Arjun/cyber-blackbox-forensics)** link!

---

## 🌟 Key Capabilities

- **📁 Multi-Source Forensic Ingestion**: Drag-and-drop or batch upload evidence files (`.csv`, `.json`, `.jsonl`, `.txt`, `.log`). Supports AWS CloudTrail, Microsoft 365, EDR telemetry, Linux Syslog, and network firewall logs.
- **🛡️ Cryptographic Evidence Vault**: Strict byte-level SHA-256 hash calculation directly from uploaded file bytes, individual log record seals, and a Master Black Box Invariant Hash guaranteeing forensic admissibility.
- **⚡ Dynamic Event Correlation Engine**: Automated chronological sorting across heterogeneous timestamp formats, entity extraction (distinguishing internal RFC1918 from external adversary IPs), patient-zero identification, and explainable risk scoring.
- **🗺️ Interactive Attack Topology Graph**: Directional graph automatically synthesized from evidence, connecting adversary C2 nodes to entrypoint workstations, lateral domain controllers, and cloud exfiltration targets.
- **🤖 FAISS Dense Vector RAG Engine**: 128-dimensional domain-weighted vectorizer with L2 normalization, `faiss.IndexFlatIP`, optional local Ollama (`llama3.2`) inference, and an offline evidence-grounded fallback engine citing retrieved log IDs and MITRE technique IDs.
- **💾 Relational Persistence (SQLite)**: Full database backing (`backend/cyber_blackbox.db`) storing incidents, evidence files, logs, attack graphs, timelines, and response playbooks with cascade deletion and incident isolation.
- **📋 Automated Containment Playbooks**: Interactive execution simulation for isolating compromised hosts, blocking adversary C2 IPs, revoking IAM credentials, and rotating accounts.
- **📄 Forensic Reports & Markdown Export**: Generate court-ready investigation reports with cryptographic chain-of-custody verification seals, printable in-browser and downloadable as `.md` documents.

---

## ⚙️ Technology Stack

### Frontend
- **React.js 18** + **Vite**
- **Tailwind CSS** (Forensic Canvas Warm Cream `#faf8f5` & Crimson Red `#dc2626` alerts)
- **Lucide React** (Forensic & security iconography)
- **Axios** (REST API client with fallback ledger resilience)

### Backend
- **Python 3.10+ / 3.14** + **FastAPI** + **Uvicorn**
- **FAISS-CPU** (Dense vector similarity search with `IndexFlatIP`)
- **NumPy** (L2-normalized mathematical vector transformations)
- **SQLite3** (Lightweight ACID relational persistence with zero external setup)
- **Pydantic v2** (Strict data models and schemas)

---

## 🚀 Quick Start Guide

### 1. Start the Backend API
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8080 --reload
```
- API Documentation (Swagger): `http://127.0.0.1:8080/docs`
- Health Endpoint: `http://127.0.0.1:8080/health`

### 2. Start the Frontend Application
```bash
cd frontend
npm install
npm run dev
```
- Open your browser at `http://localhost:5173` (or the port Vite provides)

---

## 🧪 Automated Testing

To run the complete automated test suite (27 tests across API, Correlation, Parsing, Hashing, and RAG):
```bash
cd backend
python -m pytest tests -v
```

### Test Coverage Highlights:
- `tests/test_hashing.py`: SHA-256 byte-level calculation, tamper detection, invariant property.
- `tests/test_parsers.py`: CSV, JSON arrays, JSONL, Syslog/Auth.log, 15MB file limit, empty file rejection, Latin-1 encoding resilience.
- `tests/test_correlation.py`: Chronological sorting, entity/IP extraction, MITRE classification, attack graph generation, risk scoring.
- `tests/test_rag.py`: FAISS index initialization, L2 vector normalization, cosine retrieval, forensic reasoning fallback.
- `tests/test_api.py`: Health, incident listing, evidence upload pipeline, RAG query endpoint, playbook execution, report generation, Markdown download, demo deletion protection.

---

## 🏗️ Production Build

To verify and produce an optimized production bundle of the React frontend:
```bash
cd frontend
npm run build
```
Build outputs are generated in `frontend/dist/`.
