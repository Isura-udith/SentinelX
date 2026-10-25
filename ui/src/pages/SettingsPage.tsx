import React, { useState, useEffect, useCallback } from 'react';
import {
  Settings,
  Database,
  Radio,
  Clock,
  AlertTriangle,
  Save,
  RefreshCw,
  HardDrive,
  Info,
  ExternalLink,
  ShieldCheck,
  FileText,
  Code,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Spinner } from '../components/common/Spinner';
import { tauriCommands } from '../services/tauriCommands';
import type { AppSettings, UpdateAppSettingsInput } from '../types';

interface SettingsPageProps {
  onAddToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefreshSystemStatus: () => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  onAddToast,
  onRefreshSystemStatus,
}) => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Form states
  const [theme, setTheme] = useState<string>('dark');
  const [refreshInterval, setRefreshInterval] = useState<number>(10);
  const [pageSize, setPageSize] = useState<number>(50);
  const [eventRetention, setEventRetention] = useState<number>(30);
  const [auditRetention, setAuditRetention] = useState<number>(90);
  const [pollingInterval, setPollingInterval] = useState<number>(1000);
  const [logVerbosity, setLogVerbosity] = useState<string>('INFO');
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);

  const fetchSettings = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const res = await tauriCommands.getApplicationSettings();
      setSettings(res);
      setTheme(res.theme);
      setRefreshInterval(res.refresh_interval_secs);
      setPageSize(res.event_table_page_size);
      setEventRetention(res.event_retention_days);
      setAuditRetention(res.audit_retention_days);
      setPollingInterval(res.telemetry_polling_interval_ms);
      setLogVerbosity(res.log_verbosity);
      setIsDemoMode(res.is_demo_mode);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    tauriCommands.getApplicationSettings().then(
      (res) => {
        if (!ignore) {
          setSettings(res);
          setTheme(res.theme);
          setRefreshInterval(res.refresh_interval_secs);
          setPageSize(res.event_table_page_size);
          setEventRetention(res.event_retention_days);
          setAuditRetention(res.audit_retention_days);
          setPollingInterval(res.telemetry_polling_interval_ms);
          setLogVerbosity(res.log_verbosity);
          setIsDemoMode(res.is_demo_mode);
          setIsLoading(false);
        }
      },
      (err: unknown) => {
        if (!ignore) {
          setErrorMessage(err instanceof Error ? err.message : String(err));
          setIsLoading(false);
        }
      }
    );
    return () => {
      ignore = true;
    };
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);

    const input: UpdateAppSettingsInput = {
      theme,
      refresh_interval_secs: refreshInterval,
      event_table_page_size: pageSize,
      event_retention_days: eventRetention,
      audit_retention_days: auditRetention,
      telemetry_polling_interval_ms: pollingInterval,
      log_verbosity: logVerbosity,
      is_demo_mode: isDemoMode,
    };

    try {
      const updated = await tauriCommands.updateApplicationSettings(input);
      setSettings(updated);
      onAddToast('success', 'Application settings persisted successfully.');
      onRefreshSystemStatus();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading && !settings) {
    return <Spinner label="Loading application settings..." size="lg" />;
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <Card bodyClassName="p-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Settings className="w-5 h-5 text-cyan-400" />
              <span>Application Configuration</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Configure telemetry intervals, retention schedules, and presentation preferences.
            </p>
          </div>

          <Button
            size="sm"
            variant="secondary"
            onClick={fetchSettings}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Reset Form
          </Button>
        </div>
      </Card>

      {errorMessage && (
        <div className="p-4 bg-red-950/60 border border-red-800/60 rounded-lg text-xs text-red-200">
          Settings error: {errorMessage}
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Retention Policy Card */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Data Retention & Storage Policies</span>
            </div>
          }
          subtitle="Controls automated expiration of network records and audit history"
        >
          <div className="space-y-4 text-xs">
            {/* Database Path (Read-Only) */}
            <div>
              <label className="text-slate-400 font-medium block mb-1">
                SQLite Database Location (Read-Only)
              </label>
              <div className="flex items-center gap-2 px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-slate-300">
                <HardDrive className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="truncate">{settings?.database_path}</span>
              </div>
              <p className="text-[10px] text-slate-500 mt-1">
                Safely located in standard Windows per-user LocalAppData. Database relocation is restricted to prevent corruption.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div>
                <label className="text-slate-200 font-semibold block mb-1">
                  Network Event Retention (Days)
                </label>
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={eventRetention}
                  onChange={(e) => setEventRetention(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Events older than this window will be pruned during retention cycles.
                </p>
              </div>

              <div>
                <label className="text-slate-200 font-semibold block mb-1">
                  Audit History Retention (Days)
                </label>
                <input
                  type="number"
                  min="7"
                  max="3650"
                  value={auditRetention}
                  onChange={(e) => setAuditRetention(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Compliance audit trail records retention period.
                </p>
              </div>
            </div>

            {/* Evidence Pruning Impact Notice */}
            <div className="p-3 bg-amber-950/30 border border-amber-800/40 rounded-lg flex items-start gap-2.5 text-amber-300 text-[11px]">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                <strong>Evidence Preservation Rule:</strong> Reducing event retention days will cause historical
                events supporting older alerts to be permanently pruned during the next maintenance cycle.
                Alert headers, correlation fingerprints, and audit history are always retained.
              </span>
            </div>
          </div>
        </Card>

        {/* Telemetry Polling & Demo Mode Card */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyan-400" />
              <span>Telemetry & Execution Mode</span>
            </div>
          }
          subtitle="Windows TCP connection polling frequency and collector selection"
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-slate-200 font-semibold block mb-1">
                  Telemetry Polling Interval (ms)
                </label>
                <input
                  type="number"
                  min="100"
                  max="3600000"
                  step="100"
                  value={pollingInterval}
                  onChange={(e) => setPollingInterval(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Rate at which the collector takes snapshots of the Windows TCP table (default 1000ms).
                </p>
              </div>

              <div>
                <label className="text-slate-200 font-semibold block mb-1">Log Verbosity</label>
                <select
                  value={logVerbosity}
                  onChange={(e) => setLogVerbosity(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value="DEBUG">DEBUG (Detailed Diagnostics)</option>
                  <option value="INFO">INFO (Standard Operations)</option>
                  <option value="WARN">WARN (Warnings & Errors Only)</option>
                  <option value="ERROR">ERROR (Fatal Errors Only)</option>
                </select>
              </div>
            </div>

            {/* Demo / Mock Mode Toggle */}
            <div className="pt-3 border-t border-slate-800">
              <div className="flex items-center justify-between p-3.5 bg-slate-950/80 rounded-lg border border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-100">Demonstration / Mock Mode</span>
                    {isDemoMode ? (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-400 border border-amber-700/50 font-bold uppercase">
                        ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-700/50 font-bold uppercase">
                        LIVE
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    When active, uses a deterministic in-memory mock scenario (Port Sweep) instead of querying live Windows TCP network sockets.
                  </p>
                </div>

                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isDemoMode}
                    onChange={(e) => setIsDemoMode(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-600"></div>
                </label>
              </div>
            </div>
          </div>
        </Card>

        {/* Presentation & UI Refresh Card */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Dashboard UI Preferences</span>
            </div>
          }
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="text-slate-200 font-semibold block mb-1">
                UI Automatic Refresh Interval
              </label>
              <select
                value={refreshInterval}
                onChange={(e) => setRefreshInterval(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value={5}>Every 5 seconds</option>
                <option value={10}>Every 10 seconds</option>
                <option value={30}>Every 30 seconds</option>
                <option value={60}>Every 60 seconds</option>
              </select>
            </div>

            <div>
              <label className="text-slate-200 font-semibold block mb-1">
                Default Event Table Page Size
              </label>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value={25}>25 rows</option>
                <option value={50}>50 rows</option>
                <option value={100}>100 rows</option>
                <option value={200}>200 rows</option>
              </select>
            </div>
          </div>
        </Card>

        {/* About SentinelX Section */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span>About SentinelX</span>
            </div>
          }
        >
          <div className="space-y-4 text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-cyan-950/70 border border-cyan-500/40 rounded-lg text-cyan-400 shadow-[0_0_12px_rgba(14,165,233,0.2)]">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-slate-100 flex items-center gap-1.5">
                    SentinelX <span className="text-cyan-400 font-mono text-xs">v1.0.0</span>
                  </h4>
                  <p className="text-slate-400 text-[11px]">
                    Defensive Cybersecurity Telemetry, Threat Detection & Storage Engine
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                <span className="px-2 py-0.5 bg-slate-900 border border-slate-700/60 rounded">Windows 11 x64</span>
                <span className="px-2 py-0.5 bg-cyan-950/50 border border-cyan-700/50 text-cyan-300 rounded">Tauri 2 + Rust 2024</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
              <div className="p-3 bg-slate-900/40 border border-slate-800/60 rounded-lg space-y-1">
                <span className="text-slate-400 font-semibold block text-[11px]">License & Governance</span>
                <p className="text-slate-200">MIT Open Source License</p>
                <p className="text-[11px] text-slate-400">Permissive defensive research and portfolio project.</p>
              </div>
              <div className="p-3 bg-slate-900/40 border border-slate-800/60 rounded-lg space-y-1">
                <span className="text-slate-400 font-semibold block text-[11px]">Detection Engine</span>
                <p className="text-slate-200">NET-001 (Port Scan) & NET-002 (Burst)</p>
                <p className="text-[11px] text-slate-400">In-memory sliding window state with WAL SQLite persistence.</p>
              </div>
            </div>

            <div className="p-3 bg-amber-950/20 border border-amber-800/30 rounded-lg text-amber-300/90 text-[11px] leading-relaxed">
              <strong>Defensive Scope Disclosure:</strong> SentinelX uses periodic read-only Windows TCP table snapshots via <code className="bg-slate-900 px-1 py-0.5 rounded text-amber-200">GetExtendedTcpTable</code>. It does not perform raw packet capture or payload inspection, does not install system services or kernel drivers, and does not block network traffic.
            </div>

            <div className="flex flex-wrap items-center gap-4 pt-1 border-t border-slate-800/60">
              <a
                href="https://github.com/sentinelx/sentinelx"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors text-xs font-medium"
              >
                <Code className="w-3.5 h-3.5" />
                <span>GitHub Repository</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>
              <a
                href="https://github.com/sentinelx/sentinelx/tree/master/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors text-xs font-medium"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Architecture & User Documentation</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>
            </div>
          </div>
        </Card>

        {/* Save Actions Bar */}
        <div className="flex justify-end gap-3 pt-2">
          <Button
            type="submit"
            variant="primary"
            size="md"
            isLoading={isSaving}
            leftIcon={<Save className="w-4 h-4" />}
          >
            Save Configuration
          </Button>
        </div>
      </form>
    </div>
  );
};
