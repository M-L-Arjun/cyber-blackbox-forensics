import React from 'react';
import { Shield, Server, Terminal } from 'lucide-react';

export default function DigitalForensicsDeepDive({ incident }) {
  return (
    <div className="space-y-8">
      
      {/* Root Cause Verdict Card */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-l-4 border-red-600 space-y-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#e7e2d8] pb-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-3.5 bg-red-50 rounded-xl text-red-600 border border-red-100">
              <Shield className="w-7 h-7" />
            </div>
            <div>
              <div className="text-xs font-mono text-red-700 font-extrabold uppercase tracking-wide">Root Cause Forensics Verdict</div>
              <h2 className="text-xl font-extrabold text-stone-900 mt-0.5">{incident?.title}</h2>
            </div>
          </div>

          <div className="flex items-center space-x-3 bg-white px-4 py-2 rounded-xl border border-stone-200 flex-shrink-0 shadow-sm">
            <span className="text-xs text-stone-500 font-mono font-medium">AI Confidence:</span>
            <span className="text-base font-extrabold font-mono text-emerald-700">98.4%</span>
          </div>
        </div>

        <p className="text-xs sm:text-sm text-stone-700 leading-relaxed font-sans font-medium">
          {incident?.summary}
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="bg-stone-50 p-4 rounded-xl border border-stone-200 space-y-1">
            <div className="text-[11px] font-mono text-stone-500 uppercase font-bold">Primary Threat Actor</div>
            <div className="text-sm font-bold text-red-700">{incident?.threat_actor}</div>
          </div>
          <div className="bg-stone-50 p-4 rounded-xl border border-stone-200 space-y-1">
            <div className="text-[11px] font-mono text-stone-500 uppercase font-bold">Initial Entry Vector</div>
            <div className="text-sm font-bold text-red-700 truncate">{incident?.entry_point}</div>
          </div>
          <div className="bg-stone-50 p-4 rounded-xl border border-stone-200 space-y-1">
            <div className="text-[11px] font-mono text-stone-500 uppercase font-bold">Exfiltrated Target Asset</div>
            <div className="text-sm font-bold text-amber-800">{incident?.target_asset}</div>
          </div>
        </div>
      </div>

      {/* Compromised Assets Grid & Process Tree */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Asset Inventory */}
        <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
          <div className="flex items-center space-x-3 border-b border-[#e7e2d8] pb-4">
            <Server className="w-6 h-6 text-red-600" />
            <h3 className="font-extrabold text-base text-stone-900 uppercase tracking-wider">Compromised Asset Inventory</h3>
          </div>

          <div className="space-y-3">
            {incident?.compromised_assets?.map((asset, idx) => (
              <div key={idx} className="p-4 rounded-xl bg-stone-50 border border-stone-200 flex items-center justify-between gap-4">
                <div className="flex items-center space-x-3">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping flex-shrink-0" />
                  <span className="text-xs sm:text-sm font-mono font-bold text-stone-900">{asset}</span>
                </div>
                <span className="text-xs font-mono px-3 py-1 rounded-lg bg-red-50 text-red-700 border border-red-200 font-bold flex-shrink-0">
                  ISOLATION RECOMMENDED
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Process Execution Artifact Tree */}
        <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
          <div className="flex items-center space-x-3 border-b border-[#e7e2d8] pb-4">
            <Terminal className="w-6 h-6 text-stone-800" />
            <h3 className="font-extrabold text-base text-stone-900 uppercase tracking-wider">Process Tree Artifact Analysis</h3>
          </div>

          <div className="bg-stone-50 p-5 rounded-xl border border-stone-200 font-mono text-xs sm:text-sm space-y-4 text-stone-800 leading-relaxed">
            <div className="text-stone-900 font-bold">
              ├─ explorer.exe (PID: 2840)
            </div>
            <div className="text-amber-800 pl-4 font-bold">
              └─ OUTLOOK.EXE (PID: 3912)
            </div>
            <div className="text-red-700 pl-8 font-extrabold bg-red-50 p-2.5 rounded-lg border border-red-200">
              └─ Q3_Executive_Compensation.pdf.exe (PID: 5120) [MALICIOUS PARENT]
            </div>
            <div className="text-red-800 pl-12 font-bold bg-red-100 p-3 rounded-lg border border-red-300">
              └─ powershell.exe -ExecutionPolicy Bypass -NoP -Enc aW52b2... (PID: 6044)
            </div>
            <div className="text-red-700 pl-16 text-xs sm:text-sm font-bold">
              └─ [Mimikatz LSASS Memory Dump & Credential Harvester]
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
