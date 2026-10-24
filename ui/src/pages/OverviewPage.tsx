import React from 'react';
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  Clock,
  CheckCircle,
  Radio,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import { Card, MetricCard } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Spinner } from '../components/common/Spinner';
import { ActivityChart } from '../components/charts/ActivityChart';
import { SeverityDistribution } from '../components/charts/SeverityDistribution';
import type { DashboardSummary } from '../types';
import type { NavPage } from '../components/layout/Sidebar';

interface OverviewPageProps {
  summary: DashboardSummary | null;
  isLoading: boolean;
  onNavigate: (page: NavPage) => void;
  onSelectAlert: (alertId: string) => void;
  timeRange: string;
  onTimeRangeChange: (range: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  summary,
  isLoading,
  onNavigate,
  onSelectAlert,
  timeRange,
  onTimeRangeChange,
}) => {
  if (isLoading && !summary) {
    return <Spinner label="Loading dashboard summary..." size="lg" />;
  }

  if (!summary) {
    return (
      <div className="p-8 text-center text-slate-400">
        Dashboard summary data unavailable from backend.
      </div>
    );
  }

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <MetricCard
          label="Total Events"
          value={summary.total_events.toLocaleString()}
          icon={<Activity className="w-4 h-4 text-cyan-400" />}
          subtext={`In selected range (${timeRange})`}
          tone="default"
        />

        <MetricCard
          label="Open Alerts"
          value={summary.open_alerts}
          icon={<ShieldAlert className="w-4 h-4 text-amber-400" />}
          subtext="Requires analyst review"
          tone={summary.open_alerts > 0 ? 'warning' : 'default'}
        />

        <MetricCard
          label="High / Critical"
          value={summary.high_critical_alerts}
          icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
          subtext="Immediate triage needed"
          tone={summary.high_critical_alerts > 0 ? 'danger' : 'default'}
        />

        <MetricCard
          label="Last Hour Events"
          value={summary.events_last_hour.toLocaleString()}
          icon={<Clock className="w-4 h-4 text-cyan-400" />}
          subtext="Live throughput rate"
          tone="default"
        />

        <MetricCard
          label="Collections"
          value={summary.successful_collections.toLocaleString()}
          icon={<CheckCircle className="w-4 h-4 text-emerald-400" />}
          subtext="Successful poll cycles"
          tone="success"
        />

        <MetricCard
          label="Detection Engine"
          value={summary.detection_healthy ? 'HEALTHY' : 'DEGRADED'}
          icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
          subtext="Rolling window active"
          tone={summary.detection_healthy ? 'success' : 'danger'}
        />
      </div>

      {/* Main Charts & Breakdown Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Time-Series Chart */}
        <div className="lg:col-span-2">
          <Card
            title={
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>Observation Activity Over Time</span>
              </div>
            }
            subtitle="Time-series volume of normalized network events and detected security alerts"
            headerAction={
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs">
                {['1h', '6h', '24h', '7d'].map((r) => (
                  <button
                    key={r}
                    onClick={() => onTimeRangeChange(r)}
                    className={`px-2.5 py-1 rounded font-medium transition-colors ${
                      timeRange === r
                        ? 'bg-cyan-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {r.toUpperCase()}
                  </button>
                ))}
              </div>
            }
          >
            <ActivityChart data={summary.activity_time_series} isLoading={isLoading} />
          </Card>
        </div>

        {/* Severity Distribution & Collector Quick Health */}
        <div className="space-y-6">
          <Card
            title={
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>Alert Severity Breakdown</span>
              </div>
            }
            subtitle="Active open alerts grouped by severity level"
          >
            <SeverityDistribution distribution={summary.severity_distribution} />
          </Card>

          <Card
            title={
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-emerald-400" />
                <span>Collector Status</span>
              </div>
            }
          >
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-400">Collector Name</span>
                <span className="text-slate-200 font-medium">
                  {summary.collector_status.collector_type}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-400">Status</span>
                <span
                  className={`font-semibold ${
                    summary.collector_status.is_running ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {summary.collector_status.is_running ? 'Running' : 'Stopped'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-400">Recent Duration</span>
                <span className="text-slate-200 font-mono">
                  {summary.collector_status.recent_duration_ms != null
                    ? `${summary.collector_status.recent_duration_ms.toFixed(1)} ms`
                    : 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Recent Failures</span>
                <span
                  className={`font-mono ${
                    summary.collector_status.collection_failures > 0
                      ? 'text-red-400 font-bold'
                      : 'text-slate-200'
                  }`}
                >
                  {summary.collector_status.collection_failures}
                </span>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Tables Row: Recent Alerts & Recent Events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts Table */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>Recent Security Alerts</span>
            </div>
          }
          subtitle="Latest threat detections generated by the detection engine"
          headerAction={
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('alerts')}
              rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
            >
              View All Alerts
            </Button>
          }
        >
          {summary.recent_alerts.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No recent security alerts detected
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="pb-2.5 font-semibold">Severity</th>
                    <th className="pb-2.5 font-semibold">Title / Rule</th>
                    <th className="pb-2.5 font-semibold">Observed</th>
                    <th className="pb-2.5 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {summary.recent_alerts.map((alt) => (
                    <tr
                      key={alt.id}
                      onClick={() => onSelectAlert(alt.id)}
                      className="hover:bg-slate-800/60 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5">
                        <SeverityBadge severity={alt.severity} size="sm" />
                      </td>
                      <td className="py-2.5 max-w-[200px]">
                        <div className="font-semibold text-slate-100 truncate">{alt.title}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{alt.rule_id}</div>
                      </td>
                      <td className="py-2.5 text-slate-400 font-mono">
                        {formatTimestamp(alt.last_seen)}
                      </td>
                      <td className="py-2.5">
                        <StatusBadge status={alt.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Recent Events List */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Recent Network Events</span>
            </div>
          }
          subtitle="Latest normalized connection observations"
          headerAction={
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('events')}
              rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
            >
              Investigate Events
            </Button>
          }
        >
          {summary.recent_events.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No recent network events observed
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="pb-2.5 font-semibold">Proto</th>
                    <th className="pb-2.5 font-semibold">Source</th>
                    <th className="pb-2.5 font-semibold">Destination</th>
                    <th className="pb-2.5 font-semibold">PID</th>
                    <th className="pb-2.5 font-semibold">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850 font-mono">
                  {summary.recent_events.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 text-cyan-400 font-bold">{evt.protocol}</td>
                      <td className="py-2.5 text-slate-200">
                        {evt.source_ip}:{evt.source_port}
                      </td>
                      <td className="py-2.5 text-slate-300">
                        {evt.destination_ip}:{evt.destination_port}
                      </td>
                      <td className="py-2.5 text-slate-400">
                        {evt.process_id != null ? evt.process_id : '-'}
                      </td>
                      <td className="py-2.5 text-slate-500">{formatTimestamp(evt.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
