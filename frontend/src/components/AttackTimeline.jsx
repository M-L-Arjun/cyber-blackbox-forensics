import React, { useState } from 'react';
import { Clock, ShieldAlert, FileText, ChevronRight } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function AttackTimeline({ timeline = [] }) {
  const [activeStep, setActiveStep] = useState(timeline[0] || null);

  const chartData = timeline.map((step, idx) => ({
    name: `Step ${idx + 1}`,
    time: step.time,
    severityScore: step.severity === 'Critical' ? 95 : step.severity === 'High' ? 75 : 45,
    phase: step.phase
  }));

  return (
    <div className="space-y-6">
      
      {/* Risk Progression Chart */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#e7e2d8] pb-4">
          <div className="flex items-center space-x-3">
            <Clock className="w-6 h-6 text-red-600" />
            <h3 className="font-extrabold text-base sm:text-lg uppercase tracking-wider text-stone-900">
              Incident Progression & Threat Escalation Curve
            </h3>
          </div>
          <span className="text-xs sm:text-sm font-mono text-red-700 font-extrabold">Reconstructed Timeline: 02:14:10 AM - 02:35:00 AM UTC</span>
        </div>

        <div className="h-40 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorRiskCrimson" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.35}/>
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#78716c" tick={{ fontSize: 12, fill: '#44403c' }} />
              <YAxis domain={[0, 100]} stroke="#78716c" tick={{ fontSize: 12, fill: '#44403c' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e7e2d8', borderRadius: '12px', fontSize: '13px', padding: '14px', boxShadow: '0 4px 14px rgba(0,0,0,0.08)' }}
                itemStyle={{ color: '#dc2626' }}
              />
              <Area type="monotone" dataKey="severityScore" stroke="#dc2626" strokeWidth={3} fillOpacity={1} fill="url(#colorRiskCrimson)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Interactive Timeline Cards */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl space-y-6 shadow-sm">
        <div className="flex items-center justify-between border-b border-[#e7e2d8] pb-4">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-6 h-6 text-red-600" />
            <h2 className="text-base sm:text-lg font-extrabold text-stone-900 uppercase tracking-wide">
              MITRE ATT&CK Attack Timeline
            </h2>
          </div>
          <span className="text-xs sm:text-sm font-mono text-stone-500 font-bold">
            {timeline.length} Chronological Forensic Milestones
          </span>
        </div>

        <div className="relative pl-8 space-y-6 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-1 before:bg-gradient-to-b before:from-red-600 before:via-amber-600 before:to-red-700">
          {timeline.map((step, index) => {
            const isSelected = activeStep?.id === step.id;
            const isCritical = step.severity === 'Critical';

            return (
              <div
                key={step.id}
                onClick={() => setActiveStep(step)}
                className={`relative cursor-pointer transition-all p-6 rounded-2xl border space-y-3.5 ${
                  isSelected
                    ? 'bg-white border-red-500 shadow-md ring-2 ring-red-500/20'
                    : 'bg-stone-50/70 border-[#e7e2d8] hover:border-stone-300'
                }`}
              >
                {/* Timeline Node Dot */}
                <div className={`absolute -left-[37px] top-7 w-5 h-5 rounded-full border-4 border-stone-50 ${
                  isCritical ? 'bg-red-600 animate-ping' : 'bg-amber-600'
                }`} />

                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="text-xs sm:text-sm font-mono text-red-800 font-extrabold bg-white px-3 py-1 rounded-lg border border-[#e7e2d8]">
                      {step.time}
                    </span>
                    <h3 className="font-extrabold text-base sm:text-lg text-stone-900">{step.summary}</h3>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs sm:text-sm font-mono font-extrabold px-3 py-1 rounded-lg bg-stone-100 text-stone-800 border border-stone-200">
                      {step.mitre_technique_id} - {step.mitre_technique_name}
                    </span>
                    <span className={`text-xs sm:text-sm font-extrabold px-3 py-1 rounded-lg ${
                      isCritical ? 'bg-red-100 text-red-800 border border-red-200' : 'bg-amber-100 text-amber-900 border border-amber-200'
                    }`}>
                      {step.phase}
                    </span>
                  </div>
                </div>

                <p className="text-sm sm:text-base text-stone-700 leading-relaxed font-sans font-normal">{step.description}</p>

                <div className="mt-2 flex items-center justify-between text-xs sm:text-sm font-mono text-stone-500 border-t border-[#e7e2d8] pt-3">
                  <span className="flex items-center space-x-2">
                    <FileText className="w-4 h-4 text-red-600" />
                    <span>Evidence Source: <strong className="text-stone-900 font-extrabold">{step.source}</strong></span>
                  </span>

                  <span className="text-red-700 flex items-center space-x-1 hover:underline font-extrabold">
                    <span>Inspect Evidence</span>
                    <ChevronRight className="w-4 h-4" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
