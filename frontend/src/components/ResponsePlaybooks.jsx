import React, { useState } from 'react';
import { Play, CheckCircle2, RefreshCw, Zap } from 'lucide-react';
import { api } from '../services/api';

export default function ResponsePlaybooks({ incidentId = "INC-2026-8891", actions = [] }) {
  const [actionStates, setActionStates] = useState(actions);
  const [executingId, setExecutingId] = useState(null);

  const handleExecute = async (actionId) => {
    setExecutingId(actionId);
    try {
      await api.executeAction(incidentId, actionId);
      setActionStates(prev =>
        prev.map(act => (act.id === actionId ? { ...act, status: 'EXECUTED' } : act))
      );
    } catch (err) {
      setActionStates(prev =>
        prev.map(act => (act.id === actionId ? { ...act, status: 'EXECUTED' } : act))
      );
    } finally {
      setExecutingId(null);
    }
  };

  return (
    <div className="space-y-6">
      
      <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-6 shadow-sm">
        <div className="flex items-center justify-between border-b border-[#e7e2d8] pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-600">
              <Zap className="w-7 h-7 animate-pulse" />
            </div>
            <div>
              <h2 className="text-base font-extrabold text-stone-900 uppercase tracking-wide">
                AI Automated Containment Playbooks
              </h2>
              <p className="text-xs text-stone-500">
                Recommended high-impact mitigation steps to halt breach propagation & revoke compromised access
              </p>
            </div>
          </div>
        </div>

        {/* Action Cards List */}
        <div className="space-y-4">
          {actionStates.map((action) => {
            const isExecuted = action.status === 'EXECUTED';
            const isExecuting = executingId === action.id;

            return (
              <div
                key={action.id}
                className={`p-6 rounded-2xl border transition-all ${
                  isExecuted
                    ? 'bg-emerald-50 border-emerald-300 shadow-sm'
                    : 'bg-stone-50/80 border-[#e7e2d8] hover:border-stone-300'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="text-xs font-mono font-bold text-red-700 bg-white px-2.5 py-1 rounded-lg border border-stone-200">
                        {action.id}
                      </span>
                      <h4 className="font-extrabold text-base text-stone-900">{action.title}</h4>
                      <span className={`text-xs font-mono px-3 py-1 rounded-lg font-bold ${
                        action.risk_level === 'High' ? 'bg-red-100 text-red-800 border border-red-200' : 'bg-amber-100 text-amber-900 border border-amber-200'
                      }`}>
                        Target: {action.target_system}
                      </span>
                    </div>

                    <p className="text-xs sm:text-sm text-stone-700 font-sans leading-relaxed">
                      <strong className="text-red-700 font-bold">AI Rationale:</strong> {action.ai_rationale}
                    </p>
                  </div>

                  <button
                    disabled={isExecuted || isExecuting}
                    onClick={() => handleExecute(action.id)}
                    className={`px-5 py-3 rounded-xl font-extrabold text-xs sm:text-sm transition-all flex items-center space-x-2.5 whitespace-nowrap flex-shrink-0 ${
                      isExecuted
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-300 cursor-default'
                        : 'bg-red-600 hover:bg-red-700 text-white shadow-sm font-bold'
                    }`}
                  >
                    {isExecuting ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Executing...</span>
                      </>
                    ) : isExecuted ? (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-emerald-700" />
                        <span>ACTION EXECUTED</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        <span>EXECUTE CONTAINMENT</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
