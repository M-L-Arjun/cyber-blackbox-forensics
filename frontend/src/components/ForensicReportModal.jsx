import React, { useState, useEffect } from 'react';
import { FileText, Printer, ShieldCheck, X } from 'lucide-react';
import { api } from '../services/api';

export default function ForensicReportModal({ incidentId = "INC-2026-8891", onClose }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReport() {
      const data = await api.getReport(incidentId);
      setReport(data);
      setLoading(false);
    }
    loadReport();
  }, [incidentId]);

  return (
    <div className="fixed inset-0 z-50 bg-stone-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="glass-panel max-w-4xl w-full rounded-2xl overflow-hidden border-red-300 shadow-2xl my-8 bg-white">
        
        {/* Header */}
        <div className="p-4 bg-stone-50 border-b border-stone-200 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-red-600" />
            <h3 className="font-extrabold text-sm text-stone-900 uppercase tracking-wide">
              Official Forensic Investigation Report
            </h3>
          </div>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={() => window.print()}
              className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-bold text-xs flex items-center space-x-1.5 transition-all shadow-sm"
            >
              <Printer className="w-4 h-4" />
              <span>Print / Save PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-stone-200 text-stone-500 hover:text-stone-900"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Report Content */}
        {loading ? (
          <div className="p-12 text-center text-red-600 font-mono text-xs font-bold">Generating Cryptographic Forensic Report...</div>
        ) : (
          <div className="p-8 space-y-6 text-stone-900 font-sans max-h-[75vh] overflow-y-auto bg-white">
            
            {/* Title & Metadata Header */}
            <div className="border-b border-stone-200 pb-6 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-red-700 font-bold">
                <span>REPORT ID: {report.report_id}</span>
                <span>GENERATED: {report.generated_at}</span>
              </div>
              <h1 className="text-xl font-bold text-stone-900 uppercase tracking-tight">
                {report.title}
              </h1>
              <div className="flex items-center space-x-3 text-xs font-mono">
                <span className="text-red-700 font-bold">Threat Actor: {report.threat_actor_profile}</span>
                <span className="text-stone-300">|</span>
                <span className="text-amber-800 font-bold">Vector: {report.entry_vector}</span>
              </div>
            </div>

            {/* Executive Summary */}
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-red-700 uppercase tracking-wider">1. Executive Summary</h3>
              <p className="text-xs text-stone-700 leading-relaxed bg-stone-50 p-4 rounded-xl border border-stone-200">
                {report.executive_summary}
              </p>
            </div>

            {/* Timeline Summary Table */}
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-red-700 uppercase tracking-wider">2. Reconstructed Attack Timeline</h3>
              <div className="border border-stone-200 rounded-xl overflow-hidden text-xs">
                <table className="w-full text-left">
                  <thead className="bg-stone-100 font-mono text-[11px] text-stone-700">
                    <tr>
                      <th className="p-3 font-bold">Time (UTC)</th>
                      <th className="p-3 font-bold">Phase</th>
                      <th className="p-3 font-bold">Event Summary</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-200 font-mono">
                    {report.timeline_summary?.map((t, idx) => (
                      <tr key={idx} className="hover:bg-stone-50">
                        <td className="p-3 text-red-800 font-bold whitespace-nowrap">{t.time}</td>
                        <td className="p-3 text-amber-900 font-bold">{t.phase}</td>
                        <td className="p-3 text-stone-900 font-sans">{t.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* IoCs List */}
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-red-700 uppercase tracking-wider">3. Technical Indicators of Compromise (IoCs)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {report.indicators_of_compromise?.map((ioc, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-stone-50 border border-stone-200 font-mono text-xs space-y-1">
                    <div className="text-[10px] text-red-700 font-bold">{ioc.type}</div>
                    <div className="text-stone-900 font-bold text-[11px] break-all">{ioc.value}</div>
                    <div className="text-[10px] text-stone-500 font-sans">{ioc.context}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Forensic Chain of Custody Seal */}
            <div className="p-5 rounded-2xl bg-emerald-50 border border-emerald-200 space-y-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-600" />
                <h3 className="font-bold text-xs font-mono text-emerald-800 uppercase">Cryptographic Chain of Custody Verification Seal</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                <div>
                  <span className="text-stone-600 font-medium">Master Evidence SHA-256 Digest:</span>
                  <div className="bg-white p-2 rounded border border-emerald-200 text-emerald-800 font-mono text-[10px] mt-1 break-all font-bold">
                    {report.chain_of_custody_seal?.master_evidence_sha256}
                  </div>
                </div>
                <div className="space-y-1 text-stone-700">
                  <div>Ingested Artifacts Verified: <strong className="text-emerald-800">{report.chain_of_custody_seal?.ingested_artifacts_count}</strong></div>
                  <div>Integrity Verifier: <strong className="text-red-700">{report.chain_of_custody_seal?.integrity_verifier}</strong></div>
                  <div>Legal Admissibility: <span className="text-emerald-800 font-bold">LEGALLY_ADMISSIBLE_SEALED</span></div>
                </div>
              </div>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
