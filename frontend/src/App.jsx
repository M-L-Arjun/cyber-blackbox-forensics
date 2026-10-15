import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import AttackGraph from './components/AttackGraph';
import AttackTimeline from './components/AttackTimeline';
import LogStreamVault from './components/LogStreamVault';
import RagAssistant from './components/RagAssistant';
import DigitalForensicsDeepDive from './components/DigitalForensicsDeepDive';
import ResponsePlaybooks from './components/ResponsePlaybooks';
import ComparativeBenchmark from './components/ComparativeBenchmark';
import TraditionalLogViewer from './components/TraditionalLogViewer';
import ForensicReportModal from './components/ForensicReportModal';
import EvidenceUploadModal from './components/EvidenceUploadModal';
import { api } from './services/api';
import { Shield, XCircle, CheckCircle2, TrendingUp, Sparkles, FileText } from 'lucide-react';

export default function App() {
  const [prototypeMode, setPrototypeMode] = useState('blackbox');
  const [activeTab, setActiveTab] = useState('overview');
  const [incident, setIncident] = useState(null);
  const [incidentsList, setIncidentsList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showReport, setShowReport] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);

  const fetchIncidentsList = async () => {
    try {
      const list = await api.getIncidents();
      setIncidentsList(list);
      return list;
    } catch (e) {
      console.warn("Could not load incidents list:", e);
      return [];
    }
  };

  useEffect(() => {
    async function loadInitialData() {
      const list = await fetchIncidentsList();
      const initialId = list.length > 0 ? list[0].incident_id : 'INC-2026-8891';
      const data = await api.getIncident(initialId);
      setIncident(data);
      setLoading(false);
    }
    loadInitialData();
  }, []);

  const handleSelectIncident = async (id) => {
    setLoading(true);
    try {
      const data = await api.getIncident(id);
      setIncident(data);
    } catch (err) {
      console.error("Failed to load incident:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleIncidentCreated = async (newIncident) => {
    await fetchIncidentsList();
    setIncident(newIncident);
    setActiveTab('overview');
    setPrototypeMode('blackbox');
  };

  const handleDeleteIncident = async (id) => {
    if (window.confirm(`Are you sure you want to permanently purge incident '${id}' from the database?`)) {
      setLoading(true);
      try {
        await api.deleteIncident(id);
        const updatedList = await fetchIncidentsList();
        const fallbackId = updatedList.length > 0 ? updatedList[0].incident_id : 'INC-2026-8891';
        const data = await api.getIncident(fallbackId);
        setIncident(data);
      } catch (err) {
        alert("Failed to delete incident: " + (err.response?.data?.detail || err.message));
      } finally {
        setLoading(false);
      }
    }
  };

  if (loading && !incident) {
    return (
      <div className="min-h-screen bg-[#faf8f5] flex items-center justify-center font-mono text-red-600 text-xs">
        <div className="flex items-center space-x-4 bg-white border border-[#e7e2d8] p-8 rounded-2xl shadow-lg">
          <Shield className="w-10 h-10 animate-pulse text-red-600" />
          <div>
            <div className="font-bold text-base text-stone-900 uppercase tracking-wide">Cyber Black Box Ledger</div>
            <div className="text-xs text-stone-500 mt-1">Verifying SHA-256 Invariants & Initializing FAISS RAG Engine...</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#faf8f5] text-stone-900 flex flex-col font-['Outfit',sans-serif]">
      {/* Top Navbar */}
      <Navbar
        activeIncident={incident}
        incidentsList={incidentsList}
        onSelectIncident={handleSelectIncident}
        onOpenUploadModal={() => setShowUploadModal(true)}
        onDeleteIncident={handleDeleteIncident}
        onOpenReport={() => setShowReport(true)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        prototypeMode={prototypeMode}
        setPrototypeMode={setPrototypeMode}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Incident Summary Banner */}
        <div className="glass-panel p-5 sm:p-6 rounded-2xl border-l-4 border-red-600 flex flex-col lg:flex-row lg:items-center justify-between gap-5 shadow-sm bg-white">
          <div className="space-y-2 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="px-2.5 py-0.5 rounded-md bg-red-100 text-red-800 border border-red-200 text-xs font-mono font-extrabold">
                {incident?.is_demo ? 'BASELINE DEMO' : 'LIVE INVESTIGATION'}: {incident?.incident_id}
              </span>
              <span className="text-xs text-stone-600 font-mono flex items-center space-x-1.5 font-bold">
                <span className="w-2 h-2 rounded-full bg-red-600 animate-ping" />
                <span>FORENSIC TRIAGE: {incident?.threat_actor}</span>
              </span>
              {incident?.evidence_files && incident.evidence_files.length > 0 && (
                <span className="px-2 py-0.5 rounded-md bg-stone-100 text-stone-700 border border-stone-300 text-xs font-mono">
                  {incident.evidence_files.length} Ingested File(s)
                </span>
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-stone-900 tracking-tight">{incident?.title}</h1>
            <p className="text-xs sm:text-sm text-stone-700 leading-relaxed max-w-5xl font-normal">
              {incident?.summary}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 flex-shrink-0">
            {prototypeMode !== 'traditional' ? (
              <button
                onClick={() => {
                  setPrototypeMode('traditional');
                  setActiveTab('traditional_logs');
                }}
                className="px-3.5 py-2 rounded-xl bg-stone-100 hover:bg-stone-200 text-stone-800 border border-stone-300 text-xs font-bold flex items-center space-x-1.5 transition-all shadow-sm"
              >
                <XCircle className="w-4 h-4 text-red-600" />
                <span>View Traditional Log Mode (No BlackBox)</span>
              </button>
            ) : (
              <button
                onClick={() => {
                  setPrototypeMode('blackbox');
                  setActiveTab('overview');
                }}
                className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-sm"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Switch to Cyber Black Box + RAG</span>
              </button>
            )}

            <button
              onClick={() => {
                setPrototypeMode('benchmark');
                setActiveTab('benchmark');
              }}
              className="px-3.5 py-2 rounded-xl bg-amber-50 hover:bg-amber-100 text-amber-900 border border-amber-300 text-xs font-bold flex items-center space-x-1.5 transition-all shadow-sm"
            >
              <TrendingUp className="w-4 h-4 text-amber-700" />
              <span>VS Benchmark View</span>
            </button>
          </div>
        </div>

        {/* PROTOTYPE MODE A: BLACK BOX + RAG */}
        {prototypeMode === 'blackbox' && (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <AttackGraph graph={incident?.graph} />
                <AttackTimeline timeline={incident?.timeline} />
              </div>
            )}
            {activeTab === 'vault' && (
              <LogStreamVault 
                logs={incident?.logs} 
                masterHash={incident?.master_evidence_hash} 
                evidenceFiles={incident?.evidence_files}
              />
            )}
            {activeTab === 'rag' && (
              <RagAssistant incidentId={incident?.incident_id} />
            )}
            {activeTab === 'forensics' && (
              <DigitalForensicsDeepDive incident={incident} />
            )}
            {activeTab === 'response' && (
              <ResponsePlaybooks incidentId={incident?.incident_id} actions={incident?.response_actions} />
            )}
          </>
        )}

        {/* PROTOTYPE MODE B: TRADITIONAL LOGS */}
        {prototypeMode === 'traditional' && (
          <TraditionalLogViewer />
        )}

        {/* PROTOTYPE MODE C: SIDE-BY-SIDE BENCHMARK */}
        {prototypeMode === 'benchmark' && (
          <ComparativeBenchmark />
        )}

      </main>

      {/* Evidence Upload Modal */}
      {showUploadModal && (
        <EvidenceUploadModal
          onClose={() => setShowUploadModal(false)}
          onIncidentCreated={handleIncidentCreated}
        />
      )}

      {/* Forensic Report Modal */}
      {showReport && (
        <ForensicReportModal
          incidentId={incident?.incident_id}
          onClose={() => setShowReport(false)}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-[#e7e2d8] py-5 bg-white text-center text-xs text-stone-500 font-mono">
        Cyber Black Box Digital Forensics Platform • AI Vector RAG Engine • Cryptographic Evidence Vault
      </footer>
    </div>
  );
}
