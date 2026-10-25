import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Eye,
  RefreshCw,
  X,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Pagination } from '../components/common/Pagination';
import { Spinner } from '../components/common/Spinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { tauriCommands } from '../services/tauriCommands';
import type {
  SecurityAlertSummary,
  AlertQueryParams,
  AlertSeverity,
  AlertStatus,
} from '../types';

interface AlertsPageProps {
  onSelectAlert: (alertId: string) => void;
  onAddToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onSelectAlert, onAddToast }) => {
  const [alerts, setAlerts] = useState<SecurityAlertSummary[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filters state
  const [searchText, setSearchText] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const [ruleId, setRuleId] = useState<string>('');

  // Pagination state
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);

  // Action Dialog state
  const [actionAlert, setActionAlert] = useState<{ id: string; action: 'acknowledge' | 'resolve' } | null>(null);
  const [analystNote, setAnalystNote] = useState<string>('');
  const [isActionPending, setIsActionPending] = useState<boolean>(false);

  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const params: AlertQueryParams = {
      limit,
      offset,
    };

    if (searchText.trim()) params.search_text = searchText.trim();
    if (severity) params.severity = severity as AlertSeverity;
    if (status) params.status = status as AlertStatus;
    if (ruleId) params.rule_id = ruleId;

    try {
      const res = await tauriCommands.querySecurityAlerts(params);
      setAlerts(res.items);
      setTotalCount(res.total_count);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, searchText, severity, status, ruleId]);

  useEffect(() => {
    let ignore = false;
    const params: AlertQueryParams = {
      limit,
      offset,
    };

    if (searchText.trim()) params.search_text = searchText.trim();
    if (severity) params.severity = severity as AlertSeverity;
    if (status) params.status = status as AlertStatus;
    if (ruleId) params.rule_id = ruleId;

    tauriCommands.querySecurityAlerts(params).then(
      (res) => {
        if (!ignore) {
          setAlerts(res.items);
          setTotalCount(res.total_count);
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
  }, [limit, offset, searchText, severity, status, ruleId]);

  const handlePerformAction = async () => {
    if (!actionAlert) return;
    setIsActionPending(true);

    try {
      if (actionAlert.action === 'acknowledge') {
        await tauriCommands.acknowledgeAlert(actionAlert.id, analystNote.trim() || undefined);
        onAddToast('success', `Alert ${actionAlert.id} acknowledged successfully.`);
      } else {
        await tauriCommands.resolveAlert(actionAlert.id, analystNote.trim() || undefined);
        onAddToast('success', `Alert ${actionAlert.id} marked as resolved.`);
      }
      setActionAlert(null);
      setAnalystNote('');
      await fetchAlerts();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsActionPending(false);
    }
  };

  const handleResetFilters = () => {
    setSearchText('');
    setSeverity('');
    setStatus('');
    setRuleId('');
    setOffset(0);
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}`;
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-4">
      {/* Search & Filters */}
      <Card bodyClassName="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search alert title, description, or fingerprint..."
              value={searchText}
              onChange={(e) => {
                setSearchText(e.target.value);
                setOffset(0);
              }}
              className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Filter by severity"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>

          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Filter by status"
          >
            <option value="">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Acknowledged">Acknowledged</option>
            <option value="Resolved">Resolved</option>
          </select>

          <select
            value={ruleId}
            onChange={(e) => {
              setRuleId(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Filter by rule ID"
          >
            <option value="">All Rules</option>
            <option value="NET-001">NET-001 (Port Scan)</option>
            <option value="NET-002">NET-002 (Burst)</option>
          </select>

          {(searchText || severity || status || ruleId) && (
            <Button size="sm" variant="ghost" onClick={handleResetFilters} leftIcon={<X className="w-3.5 h-3.5" />}>
              Reset
            </Button>
          )}

          <Button
            size="sm"
            variant="secondary"
            onClick={fetchAlerts}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>
        </div>
      </Card>

      {/* Alerts Table */}
      <Card bodyClassName="p-0 overflow-hidden">
        {errorMessage && (
          <div className="p-4 bg-red-950/60 border-b border-red-800/60 text-xs text-red-200">
            Error loading security alerts: {errorMessage}
          </div>
        )}

        {isLoading ? (
          <Spinner label="Loading security alerts..." size="lg" />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="No Security Alerts Found"
            description="No threat detections match the current query criteria."
            action={
              <Button size="sm" variant="secondary" onClick={handleResetFilters}>
                Clear Filter
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="px-4 py-3 font-semibold">Severity</th>
                  <th className="px-4 py-3 font-semibold">Alert Title & Fingerprint</th>
                  <th className="px-4 py-3 font-semibold">Rule ID</th>
                  <th className="px-4 py-3 font-semibold">Observations</th>
                  <th className="px-4 py-3 font-semibold">First / Last Seen</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 font-sans">
                {alerts.map((alt) => (
                  <tr
                    key={alt.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => onSelectAlert(alt.id)}
                  >
                    <td className="px-4 py-3">
                      <SeverityBadge severity={alt.severity} size="sm" />
                    </td>
                    <td className="px-4 py-3 max-w-sm">
                      <div className="font-semibold text-slate-100">{alt.title}</div>
                      <div className="text-[11px] text-slate-400 truncate">{alt.description}</div>
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {alt.fingerprint}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-cyan-400 font-bold">
                      {alt.rule_id}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      <span className="font-bold text-slate-100">{alt.event_count}</span> events
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                      <div>{formatTimestamp(alt.last_seen)}</div>
                      <div className="text-slate-500 text-[10px]">First: {formatTimestamp(alt.first_seen)}</div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={alt.status} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div
                        className="inline-flex items-center gap-1.5"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {alt.status === 'Open' && (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setActionAlert({ id: alt.id, action: 'acknowledge' })}
                            className="text-xs"
                          >
                            Acknowledge
                          </Button>
                        )}

                        {alt.status !== 'Resolved' && (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setActionAlert({ id: alt.id, action: 'resolve' })}
                            className="text-xs"
                          >
                            Resolve
                          </Button>
                        )}

                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onSelectAlert(alt.id)}
                          title="View Alert Investigation Details"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="px-5 border-t border-slate-800/80 bg-slate-950/40">
          <Pagination
            totalCount={totalCount}
            limit={limit}
            offset={offset}
            onPageChange={(newOffset) => setOffset(newOffset)}
            onLimitChange={(newLimit) => {
              setLimit(newLimit);
              setOffset(0);
            }}
            isLoading={isLoading}
          />
        </div>
      </Card>

      {/* Acknowledge / Resolve Confirmation Modal */}
      <Modal
        isOpen={actionAlert !== null}
        onClose={() => setActionAlert(null)}
        title={actionAlert?.action === 'acknowledge' ? 'Acknowledge Security Alert' : 'Resolve Security Alert'}
        description={`Transition alert state for ID: ${actionAlert?.id}`}
        footer={
          <>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setActionAlert(null)}
              disabled={isActionPending}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant={actionAlert?.action === 'resolve' ? 'primary' : 'secondary'}
              onClick={handlePerformAction}
              isLoading={isActionPending}
            >
              Confirm {actionAlert?.action === 'acknowledge' ? 'Acknowledgement' : 'Resolution'}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-xs text-slate-300">
            {actionAlert?.action === 'acknowledge'
              ? 'Acknowledging this alert records that an analyst is actively investigating the observation activity.'
              : 'Resolving this alert closes the finding in SQLite storage and records an audit log entry.'}
          </p>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Analyst Note (Optional)
            </label>
            <textarea
              value={analystNote}
              onChange={(e) => setAnalystNote(e.target.value)}
              placeholder="Add investigation context, remediation step, or root-cause notes..."
              rows={3}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
