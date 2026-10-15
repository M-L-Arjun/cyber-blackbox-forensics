import React from 'react';
import { 
  Shield, Activity, Cpu, FileText, Lock, AlertTriangle, 
  TrendingUp, XCircle, CheckCircle2, UploadCloud, Trash2, Database 
} from 'lucide-react';

export default function Navbar({ 
  activeIncident, 
  incidentsList = [],
  onSelectIncident,
  onOpenUploadModal,
  onDeleteIncident,
  onOpenReport, 
  activeTab, 
  setActiveTab, 
  prototypeMode, 
  setPrototypeMode 
}) {
  return (
    <header className="border-b border-[#e7e2d8] bg-white/95 backdrop-blur-md sticky top-0 z-40 shadow-sm">
      
      {/* 1. Top Evaluation Mode Banner */}
      <div className="bg-stone-900 text-white py-2 px-4 border-b border-stone-800">
        <div className="max-w-[1600px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2.5 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="font-extrabold tracking-wide text-stone-200">EVALUATION MODE:</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                setPrototypeMode('blackbox');
                setActiveTab('overview');
              }}
              className={`px-3 py-1 rounded-lg font-extrabold flex items-center space-x-1.5 transition-all ${
                prototypeMode === 'blackbox'
                  ? 'bg-red-600 text-white shadow-sm'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>PROTOTYPE A: WITH Black Box + RAG</span>
            </button>

            <button
              onClick={() => {
                setPrototypeMode('traditional');
                setActiveTab('traditional_logs');
              }}
              className={`px-3 py-1 rounded-lg font-extrabold flex items-center space-x-1.5 transition-all ${
                prototypeMode === 'traditional'
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <XCircle className="w-3.5 h-3.5" />
              <span>PROTOTYPE B: Traditional Logs</span>
            </button>

            <button
              onClick={() => {
                setPrototypeMode('benchmark');
                setActiveTab('benchmark');
              }}
              className={`px-3 py-1 rounded-lg font-extrabold flex items-center space-x-1.5 transition-all ${
                prototypeMode === 'benchmark'
                  ? 'bg-stone-100 text-stone-900 shadow-sm font-extrabold'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <TrendingUp className="w-3.5 h-3.5" />
              <span>SIDE-BY-SIDE BENCHMARK</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Active Evidence Incident Switcher & Action Bar */}
      <div className="bg-stone-100/90 border-b border-stone-200 px-4 py-2">
        <div className="max-w-[1600px] mx-auto flex flex-col md:flex-row items-center justify-between gap-3 text-xs">
          
          {/* Incident Selector Dropdown */}
          <div className="flex items-center space-x-2.5 w-full md:w-auto">
            <div className="flex items-center space-x-1.5 text-stone-600 font-mono font-bold flex-shrink-0">
              <Database className="w-4 h-4 text-red-600" />
              <span>INVESTIGATION VAULT:</span>
            </div>
            
            <select
              value={activeIncident?.incident_id || ''}
              onChange={(e) => onSelectIncident && onSelectIncident(e.target.value)}
              className="bg-white border border-stone-300 rounded-lg px-3 py-1.5 text-xs font-mono font-bold text-stone-800 focus:outline-none focus:border-red-500 shadow-sm truncate max-w-md w-full md:w-auto"
            >
              {incidentsList.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.is_demo ? '[DEMO]' : '[UPLOADED]'} {inc.incident_id} — {inc.title} (Risk: {inc.risk_score})
                </option>
              ))}
            </select>

            {/* Delete button if uploaded investigation */}
            {activeIncident && !activeIncident.is_demo && (
              <button
                onClick={() => onDeleteIncident && onDeleteIncident(activeIncident.incident_id)}
                title="Purge this uploaded investigation from database"
                className="p-1.5 rounded-lg text-stone-500 hover:text-red-700 hover:bg-red-50 border border-transparent hover:border-red-200 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Upload Button */}
          <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
            <button
              onClick={onOpenUploadModal}
              className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-mono font-bold text-xs flex items-center space-x-1.5 transition-all shadow-sm"
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>+ Ingest Evidence (TXT/CSV/JSON)</span>
            </button>
          </div>

        </div>
      </div>

      {/* 3. Main Navigation Header */}
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between py-3 md:h-16 gap-3">
          
          {/* Logo & Title */}
          <div className="flex items-center space-x-3 flex-shrink-0">
            <div className="p-2 rounded-xl bg-red-50 border border-red-200 text-red-600">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-wider text-stone-900 uppercase">Cyber Black Box</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-red-100 text-red-800 border border-red-200 font-mono font-extrabold">
                  {activeIncident?.is_demo ? 'DEMO LAB' : 'LIVE INVESTIGATION'}
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          {prototypeMode === 'blackbox' && (
            <nav className="flex items-center space-x-1.5 overflow-x-auto w-full md:w-auto pb-1 md:pb-0 scrollbar-none">
              {[
                { id: 'overview', label: 'Attack Graph & Timeline', icon: Activity },
                { id: 'vault', label: 'Evidence Vault (SHA-256)', icon: Lock },
                { id: 'rag', label: 'RAG AI Assistant', icon: Cpu },
                { id: 'forensics', label: 'Digital Forensics', icon: Shield },
                { id: 'response', label: 'Containment Playbooks', icon: AlertTriangle },
              ].map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-bold whitespace-nowrap transition-all ${
                      isActive
                        ? 'bg-red-600 text-white shadow-sm font-extrabold'
                        : 'text-stone-700 hover:text-stone-900 hover:bg-stone-100'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          )}

          {/* Actions & Risk Badge */}
          <div className="flex items-center space-x-3 flex-shrink-0">
            <div className="flex items-center space-x-2 bg-red-100 border border-red-200 px-3 py-1 rounded-xl">
              <span className="w-2 h-2 rounded-full bg-red-600 animate-ping" />
              <span className="text-xs font-mono font-extrabold text-red-800">
                RISK: {activeIncident?.risk_score ?? 75}/100
              </span>
            </div>

            <button
              onClick={onOpenReport}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-red-600 hover:bg-red-700 text-white font-extrabold text-xs transition-all shadow-sm whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Forensic Report</span>
            </button>
          </div>

        </div>
      </div>
    </header>
  );
}
