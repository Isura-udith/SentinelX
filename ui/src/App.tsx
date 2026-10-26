import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle } from 'lucide-react';
import { AppLayout } from './components/layout/AppLayout';
import type { NavPage } from './components/layout/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { EventsPage } from './pages/EventsPage';
import { AlertsPage } from './pages/AlertsPage';
import { AlertDetailsPage } from './pages/AlertDetailsPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { TelemetryPage } from './pages/TelemetryPage';
import { AuditPage } from './pages/AuditPage';
import { SettingsPage } from './pages/SettingsPage';
import { tauriCommands } from './services/tauriCommands';
import { subscribeToBackendEvent, BACKEND_EVENTS } from './services/tauriEvents';
import type { ToastMessage } from './components/common/Toast';
import type { SystemStatus, DashboardSummary } from './types';

let toastSequence = 0;

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<NavPage>('overview');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  // Global Backend Status & Summary
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<string>('24h');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Toasts
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((type: 'success' | 'error' | 'info', message: string) => {
    toastSequence += 1;
    const id = `toast-${Date.now()}-${toastSequence}`;
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Fetch core system status & dashboard summary
  const refreshCoreData = useCallback(async (showSpinner = true) => {
    if (showSpinner) setIsRefreshing(true);
    try {
      const [status, summary] = await Promise.all([
        tauriCommands.getSystemStatus(),
        tauriCommands.getDashboardSummary(timeRange),
      ]);
      setSystemStatus(status);
      setDashboardSummary(summary);
      setBackendError(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Failed to refresh core system state:', msg);
      setBackendError(msg);
    } finally {
      if (showSpinner) setIsRefreshing(false);
    }
  }, [timeRange]);

  // Initial load
  useEffect(() => {
    let ignore = false;
    Promise.all([
      tauriCommands.getSystemStatus(),
      tauriCommands.getDashboardSummary(timeRange),
    ])
      .then(([status, summary]) => {
        if (!ignore) {
          setSystemStatus(status);
          setDashboardSummary(summary);
          setBackendError(null);
          setIsRefreshing(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error('Failed to refresh core system state:', msg);
          setBackendError(msg);
          setIsRefreshing(false);
        }
      });
    return () => {
      ignore = true;
    };
  }, [timeRange]);

  // Periodic background refresh (default 10s or per user setting)
  useEffect(() => {
    const interval = setInterval(() => {
      refreshCoreData(false);
    }, 10000);
    return () => clearInterval(interval);
  }, [refreshCoreData]);

  // Subscribe to real-time Tauri IPC events from Rust
  useEffect(() => {
    let unlistenEvent: (() => void) | null = null;
    let unlistenAlert: (() => void) | null = null;
    let unlistenStatus: (() => void) | null = null;
    let unlistenCollector: (() => void) | null = null;

    const setupListeners = async () => {
      unlistenEvent = await subscribeToBackendEvent(BACKEND_EVENTS.NEW_EVENT, () => {
        // Refresh summary counters in background on new events
        refreshCoreData(false);
      });

      unlistenAlert = await subscribeToBackendEvent<{ alert_id: string; title: string; severity: string }>(
        BACKEND_EVENTS.NEW_ALERT,
        (payload) => {
          addToast('error', `New ${payload.severity} Alert: ${payload.title}`);
          refreshCoreData(false);
        }
      );

      unlistenStatus = await subscribeToBackendEvent(BACKEND_EVENTS.ALERT_STATUS_CHANGED, () => {
        refreshCoreData(false);
      });

      unlistenCollector = await subscribeToBackendEvent(BACKEND_EVENTS.COLLECTOR_STATE_CHANGED, () => {
        refreshCoreData(false);
      });
    };

    setupListeners();

    return () => {
      if (unlistenEvent) unlistenEvent();
      if (unlistenAlert) unlistenAlert();
      if (unlistenStatus) unlistenStatus();
      if (unlistenCollector) unlistenCollector();
    };
  }, [addToast, refreshCoreData]);

  const handleNavigate = (page: NavPage) => {
    setCurrentPage(page);
    if (page !== 'alert-details') {
      setSelectedAlertId(null);
    }
  };

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
    setCurrentPage('alert-details');
  };

  const pageMeta: Record<NavPage, { title: string; subtitle: string }> = {
    overview: {
      title: 'Security Operations Center Overview',
      subtitle: 'Real-time telemetry surveillance, threat detections, and system health',
    },
    events: {
      title: 'Normalized Network Events',
      subtitle: 'Immutable record of point-in-time network connection snapshots',
    },
    alerts: {
      title: 'Security Threat Alerts',
      subtitle: 'Active and historical security incidents flagged by heuristic detection rules',
    },
    'alert-details': {
      title: 'Alert Investigation & Evidence',
      subtitle: 'Deep inspection of correlation fingerprints and raw supporting observations',
    },
    rules: {
      title: 'Detection Rules & Heuristics',
      subtitle: 'Authoritative rule thresholds, observation windows, and state triggers',
    },
    telemetry: {
      title: 'Telemetry Collector Operations',
      subtitle: 'Live Windows TCP snapshot collector metrics, throughput, and error rates',
    },
    audit: {
      title: 'Compliance Audit Trail',
      subtitle: 'Immutable record of security transitions, configuration changes, and analyst actions',
    },
    settings: {
      title: 'Application Settings',
      subtitle: 'Configure data retention schedules, telemetry polling rate, and presentation preferences',
    },
  };

  const currentMeta = pageMeta[currentPage];

  return (
    <AppLayout
      currentPage={currentPage}
      onNavigate={handleNavigate}
      status={systemStatus}
      isRefreshing={isRefreshing}
      onRefresh={() => refreshCoreData(true)}
      pageTitle={currentMeta.title}
      pageSubtitle={currentMeta.subtitle}
      toasts={toasts}
      onDismissToast={dismissToast}
    >
      {backendError && (
        <div className="mb-4 p-3.5 bg-red-950/80 border border-red-700/80 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs text-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>
              <strong className="font-semibold text-red-100">Backend Communication Issue:</strong>{' '}
              {backendError}
            </span>
          </div>
          <button
            onClick={() => refreshCoreData(true)}
            className="px-3 py-1 bg-red-900/70 hover:bg-red-800 border border-red-600 rounded text-white font-medium transition-colors cursor-pointer"
          >
            Retry Connection
          </button>
        </div>
      )}

      {currentPage === 'overview' && (
        <OverviewPage
          summary={dashboardSummary}
          isLoading={isRefreshing}
          onNavigate={handleNavigate}
          onSelectAlert={handleSelectAlert}
          timeRange={timeRange}
          onTimeRangeChange={(r) => {
            setTimeRange(r);
          }}
        />
      )}

      {currentPage === 'events' && <EventsPage />}

      {currentPage === 'alerts' && (
        <AlertsPage onSelectAlert={handleSelectAlert} onAddToast={addToast} />
      )}

      {currentPage === 'alert-details' && selectedAlertId && (
        <AlertDetailsPage
          alertId={selectedAlertId}
          onBack={() => handleNavigate('alerts')}
          onAddToast={addToast}
        />
      )}

      {currentPage === 'rules' && <DetectionRulesPage onAddToast={addToast} />}

      {currentPage === 'telemetry' && <TelemetryPage onAddToast={addToast} />}

      {currentPage === 'audit' && <AuditPage />}

      {currentPage === 'settings' && (
        <SettingsPage
          onAddToast={addToast}
          onRefreshSystemStatus={() => refreshCoreData(false)}
        />
      )}
    </AppLayout>
  );
};

export default App;
