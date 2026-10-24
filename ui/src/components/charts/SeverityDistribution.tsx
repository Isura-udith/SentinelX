import React from 'react';
import type { AlertSeverityDistribution } from '../../types';

interface SeverityDistributionProps {
  distribution: AlertSeverityDistribution;
}

export const SeverityDistribution: React.FC<SeverityDistributionProps> = ({ distribution }) => {
  const items = [
    { label: 'Critical', count: distribution.critical, color: 'bg-red-500', barBg: 'bg-red-950/40' },
    { label: 'High', count: distribution.high, color: 'bg-orange-500', barBg: 'bg-orange-950/40' },
    { label: 'Medium', count: distribution.medium, color: 'bg-amber-500', barBg: 'bg-amber-950/40' },
    { label: 'Low', count: distribution.low, color: 'bg-blue-500', barBg: 'bg-blue-950/40' },
    { label: 'Informational', count: distribution.informational, color: 'bg-slate-500', barBg: 'bg-slate-800' },
  ];

  const total = items.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="space-y-3" aria-label="Open alerts severity distribution">
      {items.map((item) => {
        const percentage = total > 0 ? (item.count / total) * 100 : 0;
        return (
          <div key={item.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">{item.label}</span>
              <span className="text-slate-400 font-mono">
                {item.count} <span className="text-slate-500">({percentage.toFixed(0)}%)</span>
              </span>
            </div>
            <div className={`h-2 w-full rounded-full ${item.barBg} overflow-hidden`}>
              <div
                className={`h-full rounded-full transition-all duration-300 ${item.color}`}
                style={{ width: `${percentage}%` }}
              />
            </div>
          </div>
        );
      })}

      <div className="pt-2 border-t border-slate-800 flex justify-between text-xs text-slate-400 font-semibold">
        <span>Total Open Alerts</span>
        <span className="font-mono text-slate-200">{total}</span>
      </div>
    </div>
  );
};
