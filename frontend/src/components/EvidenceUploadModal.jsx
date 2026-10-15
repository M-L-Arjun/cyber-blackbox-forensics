import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, X, Shield, Loader2, Trash2 } from 'lucide-react';
import { api } from '../services/api';

const ALLOWED_EXTENSIONS = ['csv', 'json', 'jsonl', 'txt', 'log'];
const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15MB

export default function EvidenceUploadModal({ onClose, onIncidentCreated }) {
  const [files, setFiles] = useState([]);
  const [title, setTitle] = useState('');
  const [threatActor, setThreatActor] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [successInfo, setSuccessInfo] = useState(null);
  const fileInputRef = useRef(null);

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleFiles = (incomingFiles) => {
    setError(null);
    const validFiles = [];
    for (const f of incomingFiles) {
      const ext = f.name.split('.').pop().toLowerCase();
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        setError(`File '${f.name}' has unsupported format. Supported: .csv, .json, .jsonl, .txt, .log`);
        return;
      }
      if (f.size > MAX_FILE_SIZE_BYTES) {
        setError(`File '${f.name}' exceeds the 15 MB size limit.`);
        return;
      }
      if (f.size === 0) {
        setError(`File '${f.name}' is empty (0 bytes).`);
        return;
      }
      validFiles.push(f);
    }
    setFiles((prev) => [...prev, ...validFiles]);
  };

  const removeFile = (idxToRemove) => {
    setFiles((prev) => prev.filter((_, idx) => idx !== idxToRemove));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (files.length === 0) {
      setError('Please select at least one evidence log file.');
      return;
    }

    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      files.forEach((file) => {
        formData.append('files', file);
      });
      if (title.trim()) {
        formData.append('incident_title', title.trim());
      }
      if (threatActor.trim()) {
        formData.append('threat_actor', threatActor.trim());
      }

      const response = await api.uploadEvidence(formData);
      setSuccessInfo(response);
      
      // Notify parent to switch active incident
      if (response?.incident) {
        setTimeout(() => {
          onIncidentCreated(response.incident);
          onClose();
        }, 1200);
      }
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Evidence parsing and correlation failed.';
      setError(msg);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-stone-900/60 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="glass-panel max-w-2xl w-full rounded-2xl overflow-hidden border border-red-200 shadow-2xl my-8 bg-white">
        
        {/* Header */}
        <div className="p-5 bg-stone-50 border-b border-stone-200 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-red-100 text-red-700">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-extrabold text-sm sm:text-base text-stone-900 tracking-wide uppercase">
                Forensic Evidence Vault Upload
              </h3>
              <p className="text-xs text-stone-500">
                Automated multi-source parsing, SHA-256 sealing, correlation & FAISS vectorization
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={uploading}
            className="p-1.5 rounded-lg hover:bg-stone-200 text-stone-500 hover:text-stone-900 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          
          {/* Metadata Inputs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono font-bold text-stone-700 uppercase mb-1">
                Investigation Title (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. Q3 SOC Perimeter Incident"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                disabled={uploading}
                className="w-full text-xs font-sans px-3.5 py-2.5 rounded-xl border border-stone-300 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
              />
            </div>
            <div>
              <label className="block text-xs font-mono font-bold text-stone-700 uppercase mb-1">
                Suspected Threat Group (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. APT29 / CobaltStrike / Unclassified"
                value={threatActor}
                onChange={(e) => setThreatActor(e.target.value)}
                disabled={uploading}
                className="w-full text-xs font-sans px-3.5 py-2.5 rounded-xl border border-stone-300 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
              />
            </div>
          </div>

          {/* Drag and Drop Zone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              if (e.dataTransfer.files) {
                handleFiles(Array.from(e.dataTransfer.files));
              }
            }}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all ${
              isDragging
                ? 'border-red-500 bg-red-50'
                : 'border-stone-300 hover:border-red-400 bg-stone-50/60'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              multiple
              accept=".csv,.json,.jsonl,.txt,.log"
              onChange={(e) => {
                if (e.target.files) {
                  handleFiles(Array.from(e.target.files));
                }
              }}
              className="hidden"
            />
            <div className="flex flex-col items-center space-y-2">
              <div className="p-3 bg-red-100 rounded-full text-red-600">
                <UploadCloud className="w-6 h-6" />
              </div>
              <div className="text-xs sm:text-sm font-bold text-stone-800">
                Drag & drop forensic evidence files here, or <span className="text-red-600 underline">browse</span>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-1.5 text-[10px] font-mono text-stone-500">
                <span>SUPPORTED:</span>
                {ALLOWED_EXTENSIONS.map((ext) => (
                  <span key={ext} className="px-1.5 py-0.5 rounded bg-stone-200 text-stone-700 font-extrabold">
                    .{ext}
                  </span>
                ))}
                <span>• Max 15MB/file</span>
              </div>
            </div>
          </div>

          {/* Selected Files List */}
          {files.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold text-stone-700 flex items-center justify-between">
                <span>ATTACHED EVIDENCE FILES ({files.length}):</span>
                <button
                  type="button"
                  onClick={() => setFiles([])}
                  disabled={uploading}
                  className="text-red-600 hover:underline text-[11px]"
                >
                  Clear All
                </button>
              </div>
              <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1">
                {files.map((file, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2.5 rounded-xl bg-stone-100 border border-stone-200 text-xs font-mono"
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <FileText className="w-4 h-4 text-red-600 flex-shrink-0" />
                      <span className="truncate font-bold text-stone-900">{file.name}</span>
                      <span className="text-stone-500 text-[11px]">({formatFileSize(file.size)})</span>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        removeFile(idx);
                      }}
                      disabled={uploading}
                      className="p-1 rounded text-stone-400 hover:text-red-600 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span className="font-mono leading-relaxed">{error}</span>
            </div>
          )}

          {/* Success Message */}
          {successInfo && (
            <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center space-x-2 font-mono">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>{successInfo.message} Initializing investigation...</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-end space-x-3 pt-3 border-t border-stone-200">
            <button
              type="button"
              onClick={onClose}
              disabled={uploading}
              className="px-4 py-2 rounded-xl bg-stone-100 hover:bg-stone-200 text-stone-700 font-bold text-xs transition-colors"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={uploading || files.length === 0}
              className={`px-5 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 text-white shadow-sm transition-all ${
                uploading || files.length === 0
                  ? 'bg-stone-400 cursor-not-allowed'
                  : 'bg-red-600 hover:bg-red-700 active:scale-95'
              }`}
            >
              {uploading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Processing & Correlating Evidence...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>Ingest & Correlate ({files.length})</span>
                </>
              )}
            </button>
          </div>

        </form>

      </div>
    </div>
  );
}
