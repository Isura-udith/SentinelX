import React from 'react';
import type { AlertSeverity, AlertStatus } from '../../types';
import { AlertCircle, AlertTriangle, Info, CheckCircle2, ShieldAlert } from 'lucide-react';

const normalizeSeverity = (sev: string): AlertSeverity => {
  const lower = (sev || '').toLowerCase();
  switch (lower) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return 'Informational';
  }
};

const normalizeStatus = (st: string): AlertStatus => {
  const lower = (st || '').toLowerCase();
  switch (lower) {
    case 'acknowledged':
      return 'Acknowledged';
    case 'resolved':
      return 'Resolved';
    default:
      return 'Open';
  }
};

interface SeverityBadgeProps {
  severity: AlertSeverity | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const styles: Record<AlertSeverity, { bg: string; text: string; border: string; icon: React.ReactNode }> = {
    Critical: {
      bg: 'bg-red-950/40',
      text: 'text-red-400',
      border: 'border-red-800/60',
      icon: <ShieldAlert className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} aria-hidden="true" />,
    },
    High: {
      bg: 'bg-orange-950/40',
      text: 'text-orange-400',
      border: 'border-orange-800/60',
      icon: <AlertTriangle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} aria-hidden="true" />,
    },
    Medium: {
      bg: 'bg-amber-950/40',
      text: 'text-amber-400',
      border: 'border-amber-800/60',
      icon: <AlertCircle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} aria-hidden="true" />,
    },
    Low: {
      bg: 'bg-blue-950/40',
      text: 'text-blue-400',
      border: 'border-blue-800/60',
      icon: <Info className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} aria-hidden="true" />,
    },
    Informational: {
      bg: 'bg-slate-900',
      text: 'text-slate-400',
      border: 'border-slate-700',
      icon: <Info className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} aria-hidden="true" />,
    },
  };

  const normalized = normalizeSeverity(severity);
  const current = styles[normalized] || styles.Informational;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium rounded-full border ${current.bg} ${current.text} ${current.border} ${padding}`}
      role="status"
      aria-label={`Severity: ${normalized}`}
    >
      {current.icon}
      <span>{normalized}</span>
    </span>
  );
};

interface StatusBadgeProps {
  status: AlertStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const styles: Record<AlertStatus, { bg: string; text: string; border: string; icon: React.ReactNode }> = {
    Open: {
      bg: 'bg-red-950/30',
      text: 'text-red-400',
      border: 'border-red-800/40',
      icon: <AlertCircle className="w-3 h-3" aria-hidden="true" />,
    },
    Acknowledged: {
      bg: 'bg-amber-950/30',
      text: 'text-amber-400',
      border: 'border-amber-800/40',
      icon: <AlertTriangle className="w-3 h-3" aria-hidden="true" />,
    },
    Resolved: {
      bg: 'bg-emerald-950/30',
      text: 'text-emerald-400',
      border: 'border-emerald-800/40',
      icon: <CheckCircle2 className="w-3 h-3" aria-hidden="true" />,
    },
  };

  const normalized = normalizeStatus(status);
  const current = styles[normalized] || styles.Open;

  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-0.5 text-xs font-medium rounded-full border ${current.bg} ${current.text} ${current.border}`}
      role="status"
      aria-label={`Status: ${normalized}`}
    >
      {current.icon}
      <span>{normalized}</span>
    </span>
  );
};

interface StateIndicatorProps {
  healthy: boolean;
  label: string;
  sublabel?: string;
}

export const StateIndicator: React.FC<StateIndicatorProps> = ({ healthy, label, sublabel }) => {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`w-2.5 h-2.5 rounded-full ${
          healthy ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'
        }`}
        aria-hidden="true"
      />
      <div className="flex flex-col">
        <span className="text-xs font-semibold text-slate-200">{label}</span>
        {sublabel && <span className="text-[10px] text-slate-400">{sublabel}</span>}
      </div>
    </div>
  );
};
