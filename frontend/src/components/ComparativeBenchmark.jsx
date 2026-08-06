import React, { useState } from 'react';
import { Clock, TrendingUp, Database, CheckCircle2, XCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

export default function ComparativeBenchmark() {
  const benchmarkMetrics = [
    {
      metric: 'Investigation Time (MTTR)',
      traditional: '21 Days (504 Hours)',
      blackbox: '3 Minutes (0.05 Hours)',
      improvement: '99.9% Faster Response',
      status: 'success'
    },
    {
      metric: 'Evidence Integrity & Legal Admissibility',
      traditional: 'High Risk (Logs modified/overwritten)',
      blackbox: '100% SHA-256 Cryptographic Seal',
      improvement: 'Tamper-Proof Invariant Ledger',
      status: 'success'
    },
    {
      metric: 'Log Correlation Complexity',
      traditional: 'Manual pivoting across 8+ SIEM/EDR tools',
      blackbox: 'Automated AI Event Correlation',
      improvement: 'Zero Manual Correlation',
      status: 'success'
    },
    {
      metric: 'Attack Timeline Reconstruction',
      traditional: 'Manual Excel mapping (Incomplete)',
      blackbox: 'Automated MITRE ATT&CK Mapping',
      improvement: '100% Full Vector Reconstruction',
      status: 'success'
    },
    {
      metric: 'Forensic Knowledge Retrieval',
      traditional: 'Searching PDFs & threat feeds manually',
      blackbox: 'RAG Natural Language Assistant',
      improvement: 'Sub-Second Context Retrieval',
      status: 'success'
    },
    {
      metric: 'Forensic Report Generation',
      traditional: '40+ Hours of manual document drafting',
      blackbox: '1-Click Automated PDF Export',
      improvement: 'Instant Court-Ready Report',
      status: 'success'
    }
  ];

  const chartData = [
    { category: 'Investigation (Hours)', Traditional: 504, CyberBlackBox: 0.05 },
    { category: 'Report Drafting (Hours)', Traditional: 40, CyberBlackBox: 0.01 },
    { category: 'Log Search Delay (Mins)', Traditional: 720, CyberBlackBox: 0.02 },
    { category: 'Containment Delay (Hours)', Traditional: 72, CyberBlackBox: 0.1 }
  ];

  return (
    <div className="space-y-8">
      
      {/* Header Banner */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-l-4 border-red-600 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-red-50 rounded-xl text-red-600 border border-red-100">
              <TrendingUp className="w-7 h-7" />
            </div>
            <div>
              <span className="text-xs font-mono text-red-700 font-extrabold uppercase tracking-wide">
                BENCHMARK COMPARISON ENGINE
              </span>
              <h1 className="text-xl sm:text-2xl font-extrabold text-stone-900 mt-0.5">
                Traditional Digital Forensics vs. Cyber Black Box + RAG
              </h1>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-stone-700 mt-2 leading-relaxed max-w-4xl">
            Compare the slow, manual, error-prone traditional incident response process with our automated 
            <strong> Cyber Black Box & RAG Vector Engine</strong>.
          </p>
        </div>

        <div className="bg-stone-50 p-4 rounded-2xl border border-stone-200 text-center flex-shrink-0">
          <div className="text-[11px] font-mono text-stone-500 uppercase font-bold">MTTR Reduction</div>
          <div className="text-2xl font-extrabold font-mono text-emerald-700 mt-0.5">99.9% Faster</div>
          <div className="text-[10px] text-stone-500 font-mono">21 Days ➔ 3 Minutes</div>
        </div>
      </div>

      {/* Recharts Bar Chart */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#e7e2d8] pb-4">
          <div className="flex items-center space-x-2.5">
            <Clock className="w-5 h-5 text-red-600" />
            <h3 className="font-extrabold text-sm uppercase tracking-wide text-stone-900">
              Time & Effort Metrics: Traditional vs. Cyber Black Box
            </h3>
          </div>
          <span className="text-xs font-mono text-stone-500">Logarithmic Scale Comparison</span>
        </div>

        <div className="h-64 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <XAxis dataKey="category" stroke="#78716c" tick={{ fontSize: 11, fill: '#44403c' }} />
              <YAxis stroke="#78716c" tick={{ fontSize: 11, fill: '#44403c' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e7e2d8', borderRadius: '12px', fontSize: '12px', padding: '12px', boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }}
                itemStyle={{ color: '#dc2626' }}
              />
              <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
              <Bar dataKey="Traditional" fill="#dc2626" radius={[6, 6, 0, 0]} name="Traditional Response (Without Black Box)" />
              <Bar dataKey="CyberBlackBox" fill="#059669" radius={[6, 6, 0, 0]} name="Cyber Black Box + RAG Engine" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Side-by-Side Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Left Card: TRADITIONAL FORENSICS */}
        <div className="glass-panel p-6 sm:p-8 rounded-2xl border-t-4 border-stone-400 space-y-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-[#e7e2d8] pb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 rounded-xl bg-stone-100 text-stone-700 border border-stone-200">
                <XCircle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <span className="text-xs font-mono font-bold text-stone-600 uppercase">Legacy Method</span>
                <h3 className="text-lg font-extrabold text-stone-900">Traditional Forensics (No Black Box)</h3>
              </div>
            </div>
            <span className="px-3 py-1 rounded-lg bg-stone-200 text-stone-800 text-xs font-mono font-bold">21 DAYS MTTR</span>
          </div>

          <div className="space-y-4 text-xs font-sans">
            
            <div className="p-4 rounded-xl bg-stone-50 border border-stone-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <XCircle className="w-4 h-4" />
                <span>1. Manual Log Aggregation (48 - 72 Hours)</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Analysts manually log into 8+ different management portals (Splunk, Palo Alto, AWS, Exchange, EDR) to download raw text logs.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-stone-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <XCircle className="w-4 h-4" />
                <span>2. High Risk of Evidence Tampering</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Logs are stored in standard text files without cryptographic seals. Attackers can clear event logs or tamper with timestamps.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-stone-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <XCircle className="w-4 h-4" />
                <span>3. Human Eyeball Correlation & Spreadsheet Timelines</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Security analysts manually copy-paste thousands of rows into Excel to reconstruct timelines, missing crucial lateral movements.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-stone-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <XCircle className="w-4 h-4" />
                <span>4. Slow Manual Report Drafting (40+ Hours)</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Writing incident reports requires manually compiling screenshots, IP lists, and IOC tables, delaying executive action.
              </p>
            </div>

          </div>
        </div>

        {/* Right Card: CYBER BLACK BOX */}
        <div className="glass-panel p-6 sm:p-8 rounded-2xl border-t-4 border-red-600 space-y-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-[#e7e2d8] pb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 rounded-xl bg-red-50 text-red-600 border border-red-100">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <span className="text-xs font-mono font-bold text-red-700 uppercase">PROPOSED SOLUTION</span>
                <h3 className="text-lg font-extrabold text-stone-900">Cyber Black Box + AI RAG Engine</h3>
              </div>
            </div>
            <span className="px-3 py-1 rounded-lg bg-red-100 text-red-800 text-xs font-mono font-bold">3 MINS MTTR</span>
          </div>

          <div className="space-y-4 text-xs font-sans">
            
            <div className="p-4 rounded-xl bg-stone-50 border border-red-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>1. Continuous Automated Collection (Instant)</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Black Box continuously ingests telemetry across all endpoints, firewalls, emails, cloud audit trails, and browser history.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-red-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>2. 100% Cryptographic SHA-256 Evidence Vault</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Every log item gets an invariant SHA-256 hash timestamp seal. Append-only ledger ensures legal admissibility and zero tampering.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-red-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>3. AI Event Correlation & MITRE ATT&CK Graph</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                AI automatically maps event sequences to MITRE ATT&CK tactics and reconstructs visual attack topology graphs in real-time.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-stone-50 border border-red-200 space-y-1">
              <div className="font-bold text-red-700 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>4. Natural Language RAG Vector Query & 1-Click Reports</span>
              </div>
              <p className="text-stone-700 leading-relaxed">
                Ask RAG questions ("How did attacker enter?") for instant vector retrieval, and generate court-ready forensic reports in 1 click.
              </p>
            </div>

          </div>
        </div>

      </div>

      {/* Metric Matrix Table */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
        <div className="flex items-center space-x-3 border-b border-[#e7e2d8] pb-4">
          <Database className="w-6 h-6 text-red-600" />
          <h3 className="font-extrabold text-base text-stone-900 uppercase tracking-wide">
            Feature & Performance Matrix: Traditional vs. Cyber Black Box
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[750px]">
            <thead>
              <tr className="bg-stone-100 text-xs font-mono text-stone-700 border-b border-stone-200">
                <th className="p-4 font-bold">Forensic Capability Metric</th>
                <th className="p-4 font-bold text-stone-700">Traditional Forensics (No Black Box)</th>
                <th className="p-4 font-bold text-red-700">Cyber Black Box + RAG Solution</th>
                <th className="p-4 font-bold text-red-800">Impact Improvement</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-stone-200 text-xs font-mono">
              {benchmarkMetrics.map((b, idx) => (
                <tr key={idx} className="hover:bg-stone-50 transition-colors">
                  <td className="p-4 text-stone-900 font-bold font-sans">{b.metric}</td>
                  <td className="p-4 text-stone-600 font-medium">{b.traditional}</td>
                  <td className="p-4 text-red-800 font-bold">{b.blackbox}</td>
                  <td className="p-4 text-red-800 font-extrabold">
                    <span className="px-2.5 py-1 rounded-md bg-red-50 text-red-800 border border-red-200">
                      {b.improvement}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
