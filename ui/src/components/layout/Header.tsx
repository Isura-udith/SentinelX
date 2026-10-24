import React from 'react';
import { RotateCw, Database, ShieldCheck, Clock, Radio } from 'lucide-react';
import type { SystemStatus } from '../../types';

interface HeaderProps {
  title: string;
  subtitle?: string;
  status: SystemStatus | null;
  isRefreshing: boolean;
  onRefresh: () => void;
  headerAction?: React.ReactNode;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  status,
  isRefreshing,
  onRefresh,
  headerAction,
}) => {
  const formatTime = (ts: string | null) => {
    if (!ts) return 'Never';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  return (
    <header className="h-16 px-6 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between shrink-0 z-10 backdrop-blur-xs select-none">
      {/* Page Title & Context */}
      <div>
        <h1 className="text-base font-bold text-slate-100 tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>

      {/* Backend Status Area & Actions */}
      <div className="flex items-center gap-4">
        {headerAction}

        {status && (
          <div className="hidden lg:flex items-center gap-4 px-3 py-1.5 rounded-lg bg-slate-950/70 border border-slate-800 text-xs">
            {/* Collector State */}
            <div className="flex items-center gap-1.5" title={`Collector: ${status.collector_mode}`}>
              <Radio
                className={`w-3.5 h-3.5 ${
                  status.telemetry_running ? 'text-emerald-400 animate-pulse' : 'text-red-400'
                }`}
              />
              <span className="text-slate-300">
                {status.telemetry_running ? 'Collector Running' : 'Collector Stopped'}
              </span>
            </div>

            <div className="w-px h-3.5 bg-slate-800" />

            {/* Database State */}
            <div className="flex items-center gap-1.5" title={`DB: ${status.database_path}`}>
              <Database
                className={`w-3.5 h-3.5 ${
                  status.database_connected ? 'text-emerald-400' : 'text-red-400'
                }`}
              />
              <span className="text-slate-300">
                {status.database_connected ? 'SQLite Ready' : 'DB Disconnected'}
              </span>
            </div>

            <div className="w-px h-3.5 bg-slate-800" />

            {/* Detection Engine State */}
            <div className="flex items-center gap-1.5">
              <ShieldCheck
                className={`w-3.5 h-3.5 ${
                  status.detection_engine_healthy ? 'text-emerald-400' : 'text-amber-400'
                }`}
              />
              <span className="text-slate-300">
                {status.detection_engine_healthy ? 'Engine Healthy' : 'Engine Warning'}
              </span>
            </div>

            <div className="w-px h-3.5 bg-slate-800" />

            {/* Last Collection Time */}
            <div className="flex items-center gap-1.5 text-slate-400">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>{formatTime(status.last_collection_time)}</span>
            </div>

            {/* Mode Pill */}
            <div className="w-px h-3.5 bg-slate-800" />
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                status.is_demo_mode
                  ? 'bg-amber-950/80 text-amber-400 border border-amber-700/50'
                  : 'bg-emerald-950/80 text-emerald-400 border border-emerald-700/50'
              }`}
            >
              {status.is_demo_mode ? 'DEMO' : 'LIVE'}
            </span>
          </div>
        )}

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50"
          title="Refresh view from backend"
          aria-label="Refresh view"
        >
          <RotateCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>
    </header>
  );
};
