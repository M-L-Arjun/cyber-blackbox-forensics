import React, { useState } from 'react';
import { Terminal, Activity, Globe, Monitor, Server, HardDrive, ArrowRight } from 'lucide-react';

export default function AttackGraph({ graph }) {
  const [selectedNode, setSelectedNode] = useState(graph?.nodes?.[1] || null);

  const getNodeIcon = (type) => {
    switch (type) {
      case 'attacker': return Globe;
      case 'entrypoint': return Monitor;
      case 'domain_controller': return Server;
      case 'exfiltration_target': return HardDrive;
      default: return Server;
    }
  };

  const getNodeBorder = (status) => {
    switch (status) {
      case 'compromised': return 'border-red-300 bg-red-50/80 text-red-950 hover:border-red-400 shadow-sm';
      case 'suspicious': return 'border-amber-300 bg-amber-50/80 text-amber-950 hover:border-amber-400 shadow-sm';
      default: return 'border-stone-300 bg-stone-50/80 text-stone-950 hover:border-stone-400 shadow-sm';
    }
  };

  return (
    <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-6 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#e7e2d8] pb-4">
        <div>
          <div className="flex items-center space-x-3">
            <Activity className="w-6 h-6 text-red-600 animate-pulse" />
            <h2 className="text-lg sm:text-xl font-extrabold text-stone-900 uppercase tracking-wide">
              Automated Attack Topology Reconstruction
            </h2>
          </div>
          <p className="text-xs sm:text-sm text-stone-600 mt-1">
            AI-correlated graph showing initial compromise vector, lateral SMB propagation, and exfiltration egress
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs sm:text-sm font-mono">
          <span className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-red-100 text-red-800 border border-red-200 font-extrabold">
            <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping" />
            <span>Compromised Asset</span>
          </span>
          <span className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-amber-100 text-amber-900 border border-amber-200 font-extrabold">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-600" />
            <span>Exfiltration Point</span>
          </span>
        </div>
      </div>

      {/* Nodes Interactive Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 items-stretch pt-2">
        {graph?.nodes?.map((node, index) => {
          const Icon = getNodeIcon(node.type);
          const isSelected = selectedNode?.id === node.id;
          const isLast = index === (graph?.nodes?.length || 0) - 1;

          return (
            <div key={node.id} className="relative flex flex-col">
              <div
                onClick={() => setSelectedNode(node)}
                className={`flex-1 cursor-pointer transition-all duration-200 p-6 rounded-2xl border ${getNodeBorder(node.status)} ${
                  isSelected ? 'ring-2 ring-red-600 bg-white shadow-md scale-[1.02]' : 'shadow-sm'
                } space-y-4 flex flex-col justify-between`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="p-3 rounded-xl bg-white border border-[#e7e2d8] text-red-600 shadow-sm">
                      <Icon className="w-7 h-7" />
                    </div>
                    <span className="text-xs font-mono font-extrabold px-3 py-1 rounded-md uppercase bg-stone-100 border border-stone-200 text-stone-800">
                      STEP 0{index + 1}
                    </span>
                  </div>

                  <div className="font-extrabold text-base sm:text-lg text-stone-900 mb-1 leading-snug">{node.label}</div>
                  <div className="text-xs sm:text-sm font-mono text-red-700 font-extrabold mb-3">{node.ip}</div>
                </div>

                <div className="text-xs sm:text-sm text-stone-700 leading-relaxed bg-white/90 p-3.5 rounded-xl border border-[#e7e2d8] font-normal">
                  {node.details}
                </div>
              </div>

              {/* Flow Arrow */}
              {!isLast && (
                <div className="hidden lg:flex absolute -right-4 top-1/2 -translate-y-1/2 z-20 w-8 h-8 rounded-full bg-white border border-[#e7e2d8] text-red-600 items-center justify-center shadow-md">
                  <ArrowRight className="w-4 h-4" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Node Details Box */}
      {selectedNode && (
        <div className="bg-white border border-red-200 rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
          <div className="flex items-start space-x-4">
            <div className="p-4 bg-red-50 rounded-xl text-red-600 flex-shrink-0 border border-red-100">
              <Terminal className="w-7 h-7" />
            </div>
            <div className="space-y-1">
              <div className="text-xs sm:text-sm font-mono text-red-800 uppercase font-extrabold flex items-center space-x-2">
                <span>Selected Forensic Node: {selectedNode.label}</span>
                <span className="text-stone-300">•</span>
                <span className="text-stone-700 font-bold">IP: {selectedNode.ip}</span>
              </div>
              <div className="text-xs sm:text-sm text-stone-700 leading-relaxed font-sans font-medium">{selectedNode.details}</div>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-xs sm:text-sm font-mono flex-shrink-0">
            <span className="px-3.5 py-1.5 rounded-lg bg-red-100 text-red-800 border border-red-200 font-extrabold uppercase">
              STATUS: {selectedNode.status}
            </span>
          </div>
        </div>
      )}

    </div>
  );
}
