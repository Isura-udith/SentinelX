import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Sliders,
  Radio,
  History,
  Settings,
  Shield,
  FlaskConical,
} from 'lucide-react';

export type NavPage =
  | 'overview'
  | 'events'
  | 'alerts'
  | 'alert-details'
  | 'rules'
  | 'telemetry'
  | 'audit'
  | 'settings';

interface SidebarProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  isDemoMode: boolean;
  appVersion: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  isDemoMode,
  appVersion,
}) => {
  const navItems = [
    { id: 'overview' as NavPage, label: 'Overview', icon: LayoutDashboard },
    { id: 'events' as NavPage, label: 'Network Events', icon: Activity },
    { id: 'alerts' as NavPage, label: 'Security Alerts', icon: ShieldAlert },
    { id: 'rules' as NavPage, label: 'Detection Rules', icon: Sliders },
    { id: 'telemetry' as NavPage, label: 'Telemetry', icon: Radio },
    { id: 'audit' as NavPage, label: 'Audit History', icon: History },
    { id: 'settings' as NavPage, label: 'Settings', icon: Settings },
  ];

  return (
    <aside
      className="w-64 bg-slate-950 border-r border-slate-800/90 flex flex-col justify-between shrink-0 select-none h-screen"
      aria-label="Main Navigation"
    >
      <div>
        {/* App Branding */}
        <div className="px-5 py-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyan-950/60 border border-cyan-500/40 rounded-lg text-cyan-400 shadow-[0_0_12px_rgba(14,165,233,0.25)]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-bold text-base tracking-wider text-slate-100 flex items-center gap-1.5">
                SENTINEL<span className="text-cyan-400">X</span>
              </span>
              <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-widest block">
                SOC Threat Defense
              </span>
            </div>
          </div>
        </div>

        {/* Mode Indicator Banner */}
        {isDemoMode && (
          <div className="mx-3 mt-3 px-3 py-1.5 bg-amber-950/40 border border-amber-600/40 rounded-md flex items-center gap-2 text-amber-300 text-xs">
            <FlaskConical className="w-3.5 h-3.5 shrink-0" />
            <span className="font-semibold tracking-wide">DEMO / MOCK MODE</span>
          </div>
        )}

        {/* Navigation Links */}
        <nav className="p-3 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              currentPage === item.id || (currentPage === 'alert-details' && item.id === 'alerts');

            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-xs'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/80 text-[11px] text-slate-400 flex items-center justify-between">
        <span className="font-mono">v{appVersion}</span>
        <span className="text-slate-400">Windows 11 x64</span>
      </div>
    </aside>
  );
};
