import React from 'react';
import { Shield, Activity, Cpu, FileText, Lock, AlertTriangle, TrendingUp, XCircle, CheckCircle2 } from 'lucide-react';

export default function Navbar({ activeIncident, onOpenReport, activeTab, setActiveTab, prototypeMode, setPrototypeMode }) {
  return (
    <header className="border-b border-[#e7e2d8] bg-white/95 backdrop-blur-md sticky top-0 z-40 shadow-sm">
      
      {/* Top Prototype Mode Selector Banner Bar */}
      <div className="bg-stone-900 text-white py-2.5 px-4 border-b border-stone-800">
        <div className="max-w-[1600px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs sm:text-sm font-mono">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
            <span className="font-extrabold tracking-wide text-stone-200">PROTOTYPE EVALUATION MODE:</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                setPrototypeMode('blackbox');
                setActiveTab('overview');
              }}
              className={`px-3.5 py-1.5 rounded-lg font-extrabold flex items-center space-x-2 transition-all ${
                prototypeMode === 'blackbox'
                  ? 'bg-red-600 text-white shadow-sm'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>PROTOTYPE A: WITH Black Box + RAG</span>
            </button>

            <button
              onClick={() => {
                setPrototypeMode('traditional');
                setActiveTab('traditional_logs');
              }}
              className={`px-3.5 py-1.5 rounded-lg font-extrabold flex items-center space-x-2 transition-all ${
                prototypeMode === 'traditional'
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <XCircle className="w-4 h-4" />
              <span>PROTOTYPE B: WITHOUT Black Box (Traditional)</span>
            </button>

            <button
              onClick={() => {
                setPrototypeMode('benchmark');
                setActiveTab('benchmark');
              }}
              className={`px-3.5 py-1.5 rounded-lg font-extrabold flex items-center space-x-2 transition-all ${
                prototypeMode === 'benchmark'
                  ? 'bg-stone-100 text-stone-900 shadow-sm font-extrabold'
                  : 'bg-stone-800 text-stone-300 hover:bg-stone-700'
              }`}
            >
              <TrendingUp className="w-4 h-4" />
              <span>SIDE-BY-SIDE COMPARISON</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Header */}
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between py-4 md:h-20 gap-4">
          
          {/* Logo & Title */}
          <div className="flex items-center space-x-3.5 flex-shrink-0">
            <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-600">
              <Shield className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-xl tracking-wider text-stone-900 uppercase">Cyber Black Box</span>
                <span className="text-xs px-2.5 py-0.5 rounded bg-red-100 text-red-800 border border-red-200 font-mono font-extrabold">
                  AI FORENSICS v2.4
                </span>
              </div>
              <p className="text-xs sm:text-sm text-stone-500 font-sans hidden sm:block">Digital Evidence Vault & Automated Attack Timeline Reconstruction</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          {prototypeMode === 'blackbox' && (
            <nav className="flex items-center space-x-2 overflow-x-auto w-full md:w-auto pb-1 md:pb-0 scrollbar-none">
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
                    className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-bold whitespace-nowrap transition-all ${
                      isActive
                        ? 'bg-red-600 text-white shadow-sm font-extrabold'
                        : 'text-stone-700 hover:text-stone-900 hover:bg-stone-100'
                    }`}
                  >
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          )}

          {/* Actions & Risk Badge */}
          <div className="flex items-center space-x-4 flex-shrink-0">
            <div className="flex items-center space-x-2 bg-red-100 border border-red-200 px-3.5 py-1.5 rounded-xl">
              <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping" />
              <span className="text-xs sm:text-sm font-mono font-extrabold text-red-800">RISK: {activeIncident?.risk_score || 96}/100</span>
            </div>

            <button
              onClick={onOpenReport}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-700 text-white font-extrabold text-xs sm:text-sm transition-all shadow-sm whitespace-nowrap"
            >
              <FileText className="w-4 h-4" />
              <span>Export Forensic Report</span>
            </button>
          </div>

        </div>
      </div>
    </header>
  );
}
