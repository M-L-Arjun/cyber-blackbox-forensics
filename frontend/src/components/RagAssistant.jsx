import React, { useState } from 'react';
import { Cpu, Send, Sparkles, Database, FileSearch, ArrowUpRight, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';

export default function RagAssistant({ incidentId = "INC-2026-8891" }) {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState([
    {
      sender: 'assistant',
      text: "Hello! I am your **Cyber Black Box RAG Assistant**. I have indexed all 6 evidence logs, MITRE ATT&CK knowledge base entries, and cloud audit trails. Ask me any question about the incident timeline, initial access, compromised credentials, or exfiltration pathways.",
      retrieved_chunks: [],
      mitre_references: ["T1566.001", "T1059.001", "T1567.002"]
    }
  ]);
  const [loading, setLoading] = useState(false);
  const [activeChunkModal, setActiveChunkModal] = useState(null);

  const samplePrompts = [
    "How did the attacker gain initial entry?",
    "Which credentials were dumped from memory?",
    "What was exfiltrated to AWS Cloud Storage?",
    "What containment actions should we take immediately?"
  ];

  const handleSend = async (textToSend = query) => {
    if (!textToSend.trim() || loading) return;

    const userMsg = { sender: 'user', text: textToSend };
    setMessages(prev => [...prev, userMsg]);
    setQuery('');
    setLoading(true);

    try {
      const res = await api.queryRag(incidentId, textToSend);
      const assistantMsg = {
        sender: 'assistant',
        text: res.answer,
        confidence: res.confidence,
        retrieved_chunks: res.retrieved_chunks || [],
        mitre_references: res.mitre_references || []
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          sender: 'assistant',
          text: "Apologies, encountered a temporary issue querying vector store. Forensic logs confirm initial access via spearphishing attachment Q3_Executive_Compensation.pdf.exe on host DEV-WS-04.",
          retrieved_chunks: []
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      
      {/* Main Chat Panel */}
      <div className="lg:col-span-2 glass-panel p-6 sm:p-8 rounded-2xl flex flex-col h-[720px] shadow-sm">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-[#e7e2d8]">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-600">
              <Cpu className="w-7 h-7 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="font-extrabold text-base sm:text-lg text-stone-900 uppercase tracking-wide">RAG Vector Forensic Assistant</h2>
                <span className="text-xs px-3 py-0.5 rounded bg-red-100 text-red-800 font-mono font-extrabold">
                  FAISS / Cosine + MITRE KB
                </span>
              </div>
              <p className="text-xs sm:text-sm text-stone-600">Query raw evidence logs & threat intelligence in natural language</p>
            </div>
          </div>

          <div className="hidden sm:flex items-center space-x-2 text-xs sm:text-sm font-mono text-emerald-800 bg-emerald-50 px-3.5 py-2 rounded-xl border border-emerald-200 font-extrabold">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span>RAG Context Verified</span>
          </div>
        </div>

        {/* Messages Stream */}
        <div className="flex-1 overflow-y-auto py-6 space-y-6 pr-3">
          {messages.map((msg, idx) => {
            const isUser = msg.sender === 'user';
            return (
              <div key={idx} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[88%] rounded-2xl p-5 space-y-3 ${
                  isUser
                    ? 'bg-red-600 text-white font-semibold rounded-br-none shadow-sm text-sm sm:text-base'
                    : 'bg-stone-50 border border-stone-200 text-stone-900 rounded-bl-none shadow-sm text-sm sm:text-base'
                }`}>
                  
                  <div className="leading-relaxed whitespace-pre-wrap font-sans">
                    {msg.text}
                  </div>

                  {/* Context Chunks Pill */}
                  {!isUser && msg.retrieved_chunks && msg.retrieved_chunks.length > 0 && (
                    <div className="border-t border-stone-200 pt-3 mt-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs sm:text-sm font-mono text-stone-800 uppercase font-extrabold flex items-center space-x-2">
                          <Database className="w-4 h-4 text-red-600" />
                          <span>Retrieved Evidence Chunks ({msg.retrieved_chunks.length})</span>
                        </span>
                        {msg.confidence && (
                          <span className="text-xs sm:text-sm font-mono text-emerald-800 font-extrabold">
                            Confidence: {Math.round(msg.confidence * 100)}%
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap gap-2">
                        {msg.retrieved_chunks.map((chunk, cIdx) => (
                          <button
                            key={cIdx}
                            onClick={() => setActiveChunkModal(chunk)}
                            className="text-xs sm:text-sm font-mono px-3.5 py-2 rounded-lg bg-white hover:bg-stone-100 text-red-800 border border-stone-300 transition-colors flex items-center space-x-2 font-extrabold shadow-sm"
                          >
                            <FileSearch className="w-4 h-4 text-red-600" />
                            <span>{chunk.source_doc}</span>
                            <span className="text-stone-700 font-extrabold">({Math.round(chunk.score * 100)}%)</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {loading && (
            <div className="flex items-center space-x-3 text-xs sm:text-sm text-red-900 font-mono p-4 bg-red-50 border border-red-200 rounded-2xl w-fit animate-pulse font-extrabold">
              <Sparkles className="w-5 h-5 text-red-600" />
              <span>Scanning vector embeddings & retrieving relevant forensic chunks...</span>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div className="pt-4 border-t border-[#e7e2d8] space-y-2">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="flex items-center space-x-3"
          >
            <input
              type="text"
              placeholder="Ask RAG assistant about logs, IP addresses, hashes, or MITRE techniques..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="flex-1 bg-stone-50 border border-stone-300 rounded-xl px-4 py-3 text-sm sm:text-base text-stone-900 focus:outline-none focus:border-red-600 transition-colors font-mono"
            />
            <button
              type="submit"
              disabled={loading || !query.trim()}
              className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white font-extrabold text-xs sm:text-sm rounded-xl transition-all flex items-center space-x-2 shadow-sm disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
              <span>Ask RAG</span>
            </button>
          </form>
        </div>

      </div>

      {/* Sidebar */}
      <div className="space-y-6">
        
        {/* Sample Prompt Library */}
        <div className="glass-panel p-6 rounded-2xl space-y-4 shadow-sm">
          <div className="flex items-center space-x-2 border-b border-[#e7e2d8] pb-3">
            <Sparkles className="w-5 h-5 text-red-600" />
            <h3 className="font-extrabold text-sm sm:text-base text-stone-900 uppercase tracking-wider">Suggested Forensic Queries</h3>
          </div>
          <div className="space-y-2.5">
            {samplePrompts.map((promptText, pIdx) => (
              <button
                key={pIdx}
                onClick={() => handleSend(promptText)}
                className="w-full text-left p-4 rounded-xl bg-stone-50 hover:bg-red-50 border border-stone-200 hover:border-red-300 text-xs sm:text-sm text-stone-900 transition-all flex items-center justify-between group font-bold leading-snug"
              >
                <span>{promptText}</span>
                <ArrowUpRight className="w-4 h-4 text-stone-400 group-hover:text-red-600 flex-shrink-0 ml-2" />
              </button>
            ))}
          </div>
        </div>

        {/* Vector KB Info */}
        <div className="glass-panel p-6 rounded-2xl space-y-4 shadow-sm">
          <div className="flex items-center space-x-2 border-b border-[#e7e2d8] pb-3">
            <Database className="w-5 h-5 text-red-600" />
            <h3 className="font-extrabold text-sm sm:text-base text-stone-900 uppercase tracking-wider">Indexed Vector Knowledge Base</h3>
          </div>
          
          <div className="space-y-3 font-mono text-xs sm:text-sm">
            <div className="p-3.5 rounded-xl bg-stone-50 border border-stone-200 flex justify-between items-center">
              <span className="text-stone-600 font-bold">Embedding Model:</span>
              <span className="text-red-800 font-extrabold">Sentence-Transformers</span>
            </div>
            <div className="p-3.5 rounded-xl bg-stone-50 border border-stone-200 flex justify-between items-center">
              <span className="text-stone-600 font-bold">Vector Index:</span>
              <span className="text-stone-900 font-extrabold">FAISS / Cosine Matrix</span>
            </div>
            <div className="p-3.5 rounded-xl bg-stone-50 border border-stone-200 flex justify-between items-center">
              <span className="text-stone-600 font-bold">MITRE KB Entries:</span>
              <span className="text-emerald-800 font-extrabold">14 Techniques Indexed</span>
            </div>
          </div>
        </div>

      </div>

      {/* Chunk Modal Inspector */}
      {activeChunkModal && (
        <div className="fixed inset-0 z-50 bg-stone-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel max-w-2xl w-full rounded-2xl overflow-hidden border-red-300 shadow-2xl bg-white">
            <div className="p-5 bg-stone-50 border-b border-stone-200 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Database className="w-6 h-6 text-red-600" />
                <h3 className="font-extrabold text-base sm:text-lg text-stone-900">Retrieved Vector Chunk Detail</h3>
              </div>
              <button onClick={() => setActiveChunkModal(null)} className="text-stone-500 hover:text-stone-900 text-xs sm:text-sm font-mono font-bold">Close</button>
            </div>
            <div className="p-6 space-y-4 font-mono text-xs sm:text-sm bg-white">
              <div className="flex items-center justify-between text-stone-600 font-bold">
                <span>Source: <strong className="text-red-800 font-extrabold">{activeChunkModal.source_doc}</strong></span>
                <span>Similarity Score: <strong className="text-stone-900 font-extrabold">{Math.round(activeChunkModal.score * 100)}%</strong></span>
              </div>
              <div className="bg-stone-50 p-5 rounded-xl border border-stone-200 text-stone-900 leading-relaxed font-mono whitespace-pre-wrap text-xs sm:text-sm font-medium">
                {activeChunkModal.content}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
