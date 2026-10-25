import React, { useState, useEffect, useCallback } from 'react';
import {
  Radio,
  Play,
  Square,
  RefreshCw,
  Activity,
  Layers,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { Card, MetricCard } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Spinner } from '../components/common/Spinner';
import { tauriCommands } from '../services/tauriCommands';
import type { TelemetryStatus } from '../types';

interface TelemetryPageProps {
  onAddToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const TelemetryPage: React.FC<TelemetryPageProps> = ({ onAddToast }) => {
  const [status, setStatus] = useState<TelemetryStatus | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isActionPending, setIsActionPending] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const res = await tauriCommands.getTelemetryStatus();
      setStatus(res);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    tauriCommands.getTelemetryStatus().then(
      (res) => {
        if (!ignore) {
          setStatus(res);
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

  const handleStart = async () => {
    setIsActionPending(true);
    try {
      await tauriCommands.startTelemetry();
      onAddToast('success', 'Telemetry collection started.');
      await fetchStatus();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsActionPending(false);
    }
  };

  const handleStop = async () => {
    setIsActionPending(true);
    try {
      await tauriCommands.stopTelemetry();
      onAddToast('info', 'Telemetry collection stopped.');
      await fetchStatus();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsActionPending(false);
    }
  };

  const formatTimestamp = (ts: string | null) => {
    if (!ts) return 'Never';
    try {
      const d = new Date(ts);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}`;
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Info & Lifecycle Controls */}
      <Card bodyClassName="p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Radio className="w-5 h-5 text-cyan-400" />
              <span>Telemetry Collection Service</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Monitors the Windows TCP connection snapshot collector lifecycle, buffer throughput,
              and polling loop health.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {status?.is_running ? (
              <Button
                size="sm"
                variant="danger"
                onClick={handleStop}
                isLoading={isActionPending}
                leftIcon={<Square className="w-3.5 h-3.5" />}
              >
                Stop Collector
              </Button>
            ) : (
              <Button
                size="sm"
                variant="primary"
                onClick={handleStart}
                isLoading={isActionPending}
                leftIcon={<Play className="w-3.5 h-3.5" />}
              >
                Start Collector
              </Button>
            )}

            <Button
              size="sm"
              variant="secondary"
              onClick={fetchStatus}
              isLoading={isLoading}
              leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              Refresh
            </Button>
          </div>
        </div>
      </Card>

      {errorMessage && (
        <div className="p-4 bg-red-950/60 border border-red-800/60 rounded-lg text-xs text-red-200">
          Telemetry service error: {errorMessage}
        </div>
      )}

      {isLoading && !status ? (
        <Spinner label="Loading telemetry status..." size="lg" />
      ) : status ? (
        <>
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard
              label="Service State"
              value={status.is_running ? 'RUNNING' : 'STOPPED'}
              tone={status.is_running ? 'success' : 'danger'}
              icon={<Radio className="w-4 h-4" />}
              subtext={`Interval: ${status.polling_interval_ms} ms`}
            />

            <MetricCard
              label="Observed Snapshots"
              value={status.raw_records_observed.toLocaleString()}
              tone="default"
              icon={<Layers className="w-4 h-4 text-cyan-400" />}
              subtext="Raw TCP table entries"
            />

            <MetricCard
              label="Normalized Events"
              value={status.normalized_events_produced.toLocaleString()}
              tone="default"
              icon={<Activity className="w-4 h-4 text-cyan-400" />}
              subtext={`${status.skipped_records.toLocaleString()} non-established skipped`}
            />

            <MetricCard
              label="Execution Health"
              value={
                status.collection_failures === 0
                  ? '0 FAILURES'
                  : `${status.collection_failures} ERRORS`
              }
              tone={status.collection_failures === 0 ? 'success' : 'danger'}
              icon={<CheckCircle2 className="w-4 h-4" />}
              subtext={
                status.recent_duration_ms != null
                  ? `Recent duration: ${status.recent_duration_ms.toFixed(1)} ms`
                  : 'Duration unavailable'
              }
            />
          </div>

          {/* Detailed Collector Card */}
          <Card
            title={
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <span>Collector Specifications & Timestamps</span>
              </div>
            }
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Collector Subsystem:</span>
                  <span className="text-slate-200 font-bold">{status.collector_type}</span>
                </div>

                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Polling Interval:</span>
                  <span className="text-slate-200">{status.polling_interval_ms} ms</span>
                </div>

                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Last Attempt:</span>
                  <span className="text-slate-300">{formatTimestamp(status.last_attempt)}</span>
                </div>

                <div className="flex justify-between py-1">
                  <span className="text-slate-500 font-sans">Last Successful Collection:</span>
                  <span className="text-emerald-400 font-bold">{formatTimestamp(status.last_success)}</span>
                </div>
              </div>

              <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Raw Records Read:</span>
                  <span className="text-slate-200">{status.raw_records_observed}</span>
                </div>

                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Events Produced:</span>
                  <span className="text-slate-200">{status.normalized_events_produced}</span>
                </div>

                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500 font-sans">Skipped / Listening:</span>
                  <span className="text-slate-400">{status.skipped_records}</span>
                </div>

                <div className="flex justify-between py-1">
                  <span className="text-slate-500 font-sans">Consecutive Failures:</span>
                  <span className={status.collection_failures > 0 ? 'text-red-400 font-bold' : 'text-slate-200'}>
                    {status.collection_failures}
                  </span>
                </div>
              </div>
            </div>

            {status.last_error && (
              <div className="mt-4 p-4 rounded-lg bg-red-950/50 border border-red-800/60 text-xs text-red-200">
                <div className="font-bold flex items-center gap-2 mb-1">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span>Last Reported Collection Error:</span>
                </div>
                <div className="font-mono">{status.last_error}</div>
              </div>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
};
