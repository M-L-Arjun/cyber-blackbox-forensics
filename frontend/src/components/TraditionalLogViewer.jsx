import React, { useState } from 'react';
import { AlertCircle, Search, XCircle, FileCode, Edit3, Save } from 'lucide-react';

export default function TraditionalLogViewer() {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeLogFile, setActiveLogFile] = useState('syslog_auth.log');
  const [analystNotes, setAnalystNotes] = useState('');
  const [savedNotes, setSavedNotes] = useState([]);

  const rawLogFiles = {
    'syslog_auth.log': `2026-08-06T02:14:10Z auth.info sshd[4012]: Accepted password for root from 185.220.101.45 port 49202 ssh2
2026-08-06T02:14:12Z auth.warn sshd[4012]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.45
2026-08-06T02:15:00Z auth.err sudo: dev-lead : TTY=pts/1 ; PWD=/home/dev-lead ; USER=root ; COMMAND=/usr/bin/bash
2026-08-06T02:18:22Z auth.notice systemd-logind[102]: New session 42 of user root.
[WARNING: Log buffer truncated. 1,420 lines overwritten by syslog rotation]`,
    
    'workstation_edr.txt': `[EDR RAW LOG - HOST: DEV-WS-04]
02:15:32 PM - Process execution: C:\\Windows\\System32\\cmd.exe /c powershell.exe -e aW52b2tlLW1pbWlrYXR6
02:15:33 PM - Parent process: Q3_Executive_Compensation.exe (PID: 5120)
02:17:01 PM - Memory handle opened on process LSASS.EXE (Access: 0x1410)
02:19:40 PM - Process terminated: powershell.exe
[NO CRYPTOGRAPHIC HASH SEAL GENERATED - LOG MODIFIABLE BY LOCAL ADMIN]`,

    'firewall_traffic.csv': `Date,SrcIP,DstIP,DstPort,Protocol,Bytes,Action
2026-08-06 02:14:10,185.220.101.45,10.0.4.12,443,TCP,142900,ALLOW
2026-08-06 02:28:15,10.0.4.12,10.0.1.5,445,TCP,1450200,ALLOW
2026-08-06 02:35:00,185.220.101.45,52.92.16.1,443,TCP,48318382080,ALLOW
[UNORDERED RAW CSV - MANUAL PIVOT REQUIRED TO CORRELATE WITH ENDPOINT]`,

    'cloudtrail_audit.json': `{
  "eventTime": "2026-08-06T02:35:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "MultiPartUpload",
  "sourceIPAddress": "185.220.101.45",
  "requestParameters": {
    "bucketName": "aws-s3-finance-vault-production",
    "key": "db_backup_2026.tar.gz"
  },
  "userAuth": "AccessKey AKIA3910283"
}`
  };

  const handleAddNote = () => {
    if (!analystNotes.trim()) return;
    setSavedNotes(prev => [...prev, { time: new Date().toLocaleTimeString(), text: analystNotes }]);
    setAnalystNotes('');
  };

  return (
    <div className="space-y-6">
      
      {/* Warning Header */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-l-4 border-red-600 bg-red-50/40 space-y-4 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="p-3.5 bg-red-100 text-red-700 rounded-xl border border-red-200">
            <XCircle className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs sm:text-sm font-mono font-extrabold text-red-700 uppercase">PROTOTYPE MODE: TRADITIONAL LOG VIEWER</span>
              <span className="text-xs px-2.5 py-0.5 rounded bg-red-100 text-red-800 font-mono font-extrabold">WITHOUT BLACK BOX & RAG</span>
            </div>
            <h2 className="text-lg sm:text-xl font-extrabold text-stone-900 mt-0.5">
              Un-correlated Raw Telemetry Files (Manual Investigation)
            </h2>
          </div>
        </div>

        <p className="text-xs sm:text-sm text-stone-700 leading-relaxed font-sans font-medium">
          This view demonstrates how security analysts must traditionally operate: manually logging into separate consoles, 
          reading raw un-indexed text logs, manually cross-referencing timestamps, with <strong>zero SHA-256 evidence integrity seals</strong> and <strong>no AI vector search assistance</strong>.
        </p>

        <div className="flex flex-wrap items-center gap-4 text-xs sm:text-sm font-mono pt-1 text-stone-700 font-bold">
          <span className="flex items-center space-x-2 text-red-700 font-extrabold">
            <AlertCircle className="w-4 h-4 text-red-600" />
            <span>Integrity Seal: UNSEALED / MODIFIABLE</span>
          </span>
          <span>•</span>
          <span>Correlation: MANUAL SPREADSHEET</span>
          <span>•</span>
          <span>Avg Investigation Delay: 21 DAYS</span>
        </div>
      </div>

      {/* Main Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Log Viewer */}
        <div className="lg:col-span-2 glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#e7e2d8] pb-4">
            <div className="flex items-center space-x-3">
              <FileCode className="w-6 h-6 text-stone-800" />
              <h3 className="font-extrabold text-base text-stone-900 uppercase">Raw Log Files Browser</h3>
            </div>

            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 absolute left-3.5 top-3.5 text-stone-400" />
              <input
                type="text"
                placeholder="Un-indexed grep search..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-stone-50 border border-stone-300 rounded-xl pl-10 pr-3 py-2.5 text-xs sm:text-sm text-stone-900 focus:outline-none focus:border-red-600 font-mono"
              />
            </div>
          </div>

          <div className="flex space-x-2 overflow-x-auto pb-1">
            {Object.keys(rawLogFiles).map(fileName => (
              <button
                key={fileName}
                onClick={() => setActiveLogFile(fileName)}
                className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-mono font-extrabold whitespace-nowrap transition-all ${
                  activeLogFile === fileName
                    ? 'bg-red-600 text-white shadow-sm font-extrabold'
                    : 'bg-stone-100 text-stone-700 hover:bg-stone-200'
                }`}
              >
                {fileName}
              </button>
            ))}
          </div>

          <div className="bg-stone-900 text-stone-100 p-6 rounded-2xl font-mono text-xs sm:text-sm leading-relaxed overflow-x-auto min-h-[400px] shadow-inner space-y-3 border border-stone-800">
            <div className="text-slate-400 text-xs border-b border-stone-800 pb-2 mb-3 flex justify-between font-bold">
              <span>FILE: /var/log/security/{activeLogFile}</span>
              <span className="text-red-400 font-extrabold">UNSEALED LOG</span>
            </div>

            <pre className="whitespace-pre-wrap text-emerald-400 font-mono text-xs sm:text-sm">
              {rawLogFiles[activeLogFile]}
            </pre>
          </div>

        </div>

        {/* Scratchpad */}
        <div className="space-y-6">
          
          <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
            <div className="flex items-center space-x-3 border-b border-[#e7e2d8] pb-3">
              <Edit3 className="w-6 h-6 text-stone-800" />
              <h3 className="font-extrabold text-base text-stone-900 uppercase">Manual Analyst Scratchpad</h3>
            </div>

            <p className="text-xs sm:text-sm text-stone-600">
              Without AI correlation or RAG query assistance, analysts must write down timestamps and IP addresses manually in notes.
            </p>

            <div className="space-y-3">
              <textarea
                rows={4}
                placeholder="Type manual findings (e.g. 'Found IP 185.220.101.45 at 02:14 AM on DEV-WS-04...')"
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                className="w-full bg-stone-50 border border-stone-300 rounded-xl p-3.5 text-xs sm:text-sm text-stone-900 focus:outline-none focus:border-red-600 font-mono"
              />

              <button
                onClick={handleAddNote}
                className="w-full py-3 bg-red-600 hover:bg-red-700 text-white font-extrabold text-xs sm:text-sm rounded-xl transition-all flex items-center justify-center space-x-2 shadow-sm"
              >
                <Save className="w-4 h-4" />
                <span>Save Manual Finding Note</span>
              </button>
            </div>

            {savedNotes.length > 0 && (
              <div className="pt-3 border-t border-stone-200 space-y-2">
                <span className="text-xs font-mono font-extrabold text-stone-600 uppercase">Saved Notes ({savedNotes.length})</span>
                {savedNotes.map((note, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-stone-100 border border-stone-200 text-xs sm:text-sm font-mono text-stone-900 space-y-1">
                    <span className="text-xs text-stone-500 font-bold">{note.time}</span>
                    <div>{note.text}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="glass-panel p-6 rounded-2xl space-y-3 border-l-4 border-red-600 shadow-sm bg-red-50/40">
            <h4 className="font-extrabold text-xs sm:text-sm text-red-800 uppercase tracking-wide">
              Key Bottlenecks in Traditional Method
            </h4>
            <ul className="text-xs sm:text-sm text-stone-700 space-y-2 list-disc pl-4 font-sans leading-relaxed">
              <li><strong>No Automatic SHA-256 Seal:</strong> Evidence can be modified or overwritten by local administrative privileges.</li>
              <li><strong>No MITRE Mapping:</strong> Requires analyst to manually search technique IDs on mitre.org.</li>
              <li><strong>No RAG Search:</strong> Natural language questions cannot be answered automatically.</li>
            </ul>
          </div>

        </div>

      </div>
    </div>
  );
}
