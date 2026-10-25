import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowLeft,
  Clock,
  Layers,
  Fingerprint,
  Activity,
  History,
  AlertTriangle,
  CheckCircle2,
  Calendar,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Spinner } from '../components/common/Spinner';
import { Modal } from '../components/common/Modal';
import { tauriCommands } from '../services/tauriCommands';
import type {
  SecurityAlertDetails,
  NetworkEventSummary,
} from '../types';

interface AlertDetailsPageProps {
  alertId: string;
  onBack: () => void;
  onAddToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const AlertDetailsPage: React.FC<AlertDetailsPageProps> = ({
  alertId,
  onBack,
  onAddToast,
}) => {
  const [details, setDetails] = useState<SecurityAlertDetails | null>(null);
  const [evidenceEvents, setEvidenceEvents] = useState<NetworkEventSummary[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Action Dialog state
  const [actionType, setActionType] = useState<'acknowledge' | 'resolve' | null>(null);
  const [analystNote, setAnalystNote] = useState<string>('');
  const [isActionPending, setIsActionPending] = useState<boolean>(false);

  const fetchAlertDetails = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const [d, ev] = await Promise.all([
        tauriCommands.getSecurityAlertDetails(alertId),
        tauriCommands.getAlertEvidence(alertId),
      ]);
      setDetails(d);
      setEvidenceEvents(ev);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    let ignore = false;
    Promise.all([
      tauriCommands.getSecurityAlertDetails(alertId),
      tauriCommands.getAlertEvidence(alertId),
    ]).then(
      ([d, ev]) => {
        if (!ignore) {
          setDetails(d);
          setEvidenceEvents(ev);
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
  }, [alertId]);

  const handlePerformAction = async () => {
    if (!actionType) return;
    setIsActionPending(true);

    try {
      if (actionType === 'acknowledge') {
        await tauriCommands.acknowledgeAlert(alertId, analystNote.trim() || undefined);
        onAddToast('success', `Alert ${alertId} acknowledged.`);
      } else {
        await tauriCommands.resolveAlert(alertId, analystNote.trim() || undefined);
        onAddToast('success', `Alert ${alertId} resolved.`);
      }
      setActionType(null);
      setAnalystNote('');
      await fetchAlertDetails();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsActionPending(false);
    }
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}`;
    } catch {
      return ts;
    }
  };

  if (isLoading && !details) {
    return <Spinner label="Loading alert investigation..." size="lg" />;
  }

  if (errorMessage || !details) {
    return (
      <div className="space-y-4">
        <Button size="sm" variant="secondary" onClick={onBack} leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}>
          Back to Alerts
        </Button>
        <Card bodyClassName="p-8 text-center text-red-400">
          Failed to load alert details: {errorMessage || 'Not found'}
        </Card>
      </div>
    );
  }

  const isEvidencePruned = details.evidence_event_ids.length > 0 && evidenceEvents.length === 0;

  return (
    <div className="space-y-6">
      {/* Top Bar with Navigation & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Button size="sm" variant="secondary" onClick={onBack} leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}>
          Back to Alerts List
        </Button>

        <div className="flex items-center gap-2">
          {details.status?.toLowerCase() === 'open' && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setActionType('acknowledge')}
              leftIcon={<Clock className="w-3.5 h-3.5" />}
            >
              Acknowledge Alert
            </Button>
          )}

          {details.status?.toLowerCase() !== 'resolved' && (
            <Button
              size="sm"
              variant="primary"
              onClick={() => setActionType('resolve')}
              leftIcon={<CheckCircle2 className="w-3.5 h-3.5" />}
            >
              Resolve Alert
            </Button>
          )}
        </div>
      </div>

      {/* Main Alert Identity Card */}
      <Card bodyClassName="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={details.severity} />
              <StatusBadge status={details.status} />
              <span className="font-mono text-xs text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                {details.rule_id} v{details.rule_version}
              </span>
            </div>

            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              {details.title}
            </h2>

            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              {details.description}
            </p>
          </div>

          <div className="text-right text-xs text-slate-400 space-y-1 bg-slate-950/60 p-3 rounded-lg border border-slate-800 font-mono">
            <div>
              <span className="text-slate-500">Alert ID: </span>
              <span className="text-slate-200">{details.id}</span>
            </div>
            <div>
              <span className="text-slate-500">First Seen: </span>
              <span className="text-slate-300">{formatTimestamp(details.first_seen)}</span>
            </div>
            <div>
              <span className="text-slate-500">Last Seen: </span>
              <span className="text-slate-300">{formatTimestamp(details.last_seen)}</span>
            </div>
          </div>
        </div>

        {/* Correlation & Investigation Metadata */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6 pt-6 border-t border-slate-800 text-xs">
          <div className="flex items-start gap-3 bg-slate-950/40 p-3 rounded-lg border border-slate-800/80">
            <Fingerprint className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">
                Correlation Fingerprint
              </span>
              <span className="font-mono text-slate-200 break-all">{details.fingerprint}</span>
            </div>
          </div>

          <div className="flex items-start gap-3 bg-slate-950/40 p-3 rounded-lg border border-slate-800/80">
            <Layers className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">
                Supporting Evidence Count
              </span>
              <span className="text-slate-200 font-medium">
                <span className="font-bold text-slate-100 font-mono">{details.event_count}</span> total observations
                ({details.evidence_event_ids?.length ?? 0} linked IDs)
              </span>
            </div>
          </div>

          <div className="flex items-start gap-3 bg-slate-950/40 p-3 rounded-lg border border-slate-800/80">
            <Calendar className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">
                Audit State
              </span>
              <span className="text-slate-200">
                {details.associated_audit_history?.length ?? 0} logged state transitions
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* Supporting Evidence Events Section */}
      <Card
        title={
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>Supporting Network Observations</span>
          </div>
        }
        subtitle="Underlying network connection events correlated into this detection"
      >
        {isEvidencePruned && (
          <div className="p-3 mb-4 rounded-lg bg-amber-950/40 border border-amber-600/40 flex items-center gap-2.5 text-xs text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
            <span>
              Supporting evidence records have expired according to the configured SQLite retention policy.
              The alert metadata and correlation fingerprint remain preserved.
            </span>
          </div>
        )}

        {evidenceEvents.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500">
            {isEvidencePruned
              ? 'No raw evidence records available (pruned by retention).'
              : 'No supporting events found.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px] font-sans">
                <tr>
                  <th className="pb-2.5 font-semibold">Timestamp</th>
                  <th className="pb-2.5 font-semibold">Proto</th>
                  <th className="pb-2.5 font-semibold">Source Address : Port</th>
                  <th className="pb-2.5 font-semibold">Destination Address : Port</th>
                  <th className="pb-2.5 font-semibold">PID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {evidenceEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 text-slate-400">{formatTimestamp(ev.timestamp)}</td>
                    <td className="py-2.5 text-cyan-400 font-bold font-sans">{ev.protocol}</td>
                    <td className="py-2.5 text-slate-200">{ev.source_ip}:{ev.source_port}</td>
                    <td className="py-2.5 text-slate-100 font-semibold">{ev.destination_ip}:{ev.destination_port}</td>
                    <td className="py-2.5 text-slate-400">{ev.process_id != null ? ev.process_id : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Investigation Timeline & Audit History */}
      <Card
        title={
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <span>Investigation Timeline & Audit Trail</span>
          </div>
        }
        subtitle="Chronological record of detections, acknowledgements, and analyst actions"
      >
        {(details.associated_audit_history?.length ?? 0) === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500">
            No audit records associated with this alert.
          </div>
        ) : (
          <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-800">
            {details.associated_audit_history?.map((entry) => (
              <div key={entry.id} className="relative flex items-start gap-4 pl-8 text-xs">
                <div className="absolute left-2.5 top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-500 ring-4 ring-slate-900" />
                <div className="flex-1 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between font-semibold text-slate-200">
                    <span>{entry.action}</span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {formatTimestamp(entry.timestamp)}
                    </span>
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Actor: <span className="text-slate-300 font-mono">{entry.actor}</span>
                  </div>
                  {entry.details && Object.keys(entry.details).length > 0 && (
                    <pre className="mt-2 p-2 bg-slate-950 rounded text-[10px] text-slate-400 font-mono overflow-x-auto">
                      {JSON.stringify(entry.details, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Acknowledge / Resolve Modal */}
      <Modal
        isOpen={actionType !== null}
        onClose={() => setActionType(null)}
        title={actionType === 'acknowledge' ? 'Acknowledge Alert' : 'Resolve Alert'}
        description={`Record analyst action for alert ${details.id}`}
        footer={
          <>
            <Button size="sm" variant="secondary" onClick={() => setActionType(null)} disabled={isActionPending}>
              Cancel
            </Button>
            <Button
              size="sm"
              variant={actionType === 'resolve' ? 'primary' : 'secondary'}
              onClick={handlePerformAction}
              isLoading={isActionPending}
            >
              Confirm
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-xs text-slate-300">
            {actionType === 'acknowledge'
              ? 'Transition this alert to Acknowledged. This notifies the SOC that an investigation is active.'
              : 'Transition this alert to Resolved and record closing findings into SQLite persistence.'}
          </p>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Analyst Note (Optional)
            </label>
            <textarea
              value={analystNote}
              onChange={(e) => setAnalystNote(e.target.value)}
              placeholder="Enter investigation notes or remediation details..."
              rows={3}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
