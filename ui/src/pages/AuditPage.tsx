import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  RefreshCw,
  Eye,
  X,
  User,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Pagination } from '../components/common/Pagination';
import { Spinner } from '../components/common/Spinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { tauriCommands } from '../services/tauriCommands';
import type { AuditEntry, AuditQueryParams } from '../types';

export const AuditPage: React.FC = () => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>('');
  const [targetTypeFilter, setTargetTypeFilter] = useState<string>('');
  const [actorFilter, setActorFilter] = useState<string>('');

  // Pagination
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);

  // Detail Modal
  const [selectedEntry, setSelectedEntry] = useState<AuditEntry | null>(null);

  const fetchAuditHistory = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const params: AuditQueryParams = {
      limit,
      offset,
    };

    if (actionFilter) params.action = actionFilter;
    if (targetTypeFilter) params.target_type = targetTypeFilter;
    if (actorFilter.trim()) params.actor = actorFilter.trim();

    try {
      const res = await tauriCommands.getAuditHistory(params);
      setEntries(res.items);
      setTotalCount(res.total_count);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, actionFilter, targetTypeFilter, actorFilter]);

  useEffect(() => {
    let ignore = false;
    const params: AuditQueryParams = {
      limit,
      offset,
    };
    if (actionFilter) params.action = actionFilter;
    if (targetTypeFilter) params.target_type = targetTypeFilter;
    if (actorFilter.trim()) params.actor = actorFilter.trim();

    tauriCommands.getAuditHistory(params).then(
      (res) => {
        if (!ignore) {
          setEntries(res.items);
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
  }, [limit, offset, actionFilter, targetTypeFilter, actorFilter]);

  const handleResetFilters = () => {
    setActionFilter('');
    setTargetTypeFilter('');
    setActorFilter('');
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
      {/* Header Context & Filters */}
      <Card bodyClassName="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 text-slate-300 text-xs font-semibold mr-2">
            <History className="w-4 h-4 text-cyan-400" />
            <span>Audit Trail (Read-Only)</span>
          </div>

          <select
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Filter by action"
          >
            <option value="">All Actions</option>
            <option value="alert_created">alert_created</option>
            <option value="alert_acknowledged">alert_acknowledged</option>
            <option value="alert_resolved">alert_resolved</option>
            <option value="rule_updated">rule_updated</option>
            <option value="settings_updated">settings_updated</option>
          </select>

          <select
            value={targetTypeFilter}
            onChange={(e) => {
              setTargetTypeFilter(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Filter by target type"
          >
            <option value="">All Target Types</option>
            <option value="alert">alert</option>
            <option value="rule">rule</option>
            <option value="settings">settings</option>
          </select>

          <input
            type="text"
            placeholder="Filter by Actor..."
            value={actorFilter}
            onChange={(e) => {
              setActorFilter(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 w-44 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />

          {(actionFilter || targetTypeFilter || actorFilter) && (
            <Button size="sm" variant="ghost" onClick={handleResetFilters} leftIcon={<X className="w-3.5 h-3.5" />}>
              Reset
            </Button>
          )}

          <Button
            size="sm"
            variant="secondary"
            onClick={fetchAuditHistory}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>
        </div>
      </Card>

      {/* Audit Log Table */}
      <Card bodyClassName="p-0 overflow-hidden">
        {errorMessage && (
          <div className="p-4 bg-red-950/60 border-b border-red-800/60 text-xs text-red-200">
            Error reading audit repository: {errorMessage}
          </div>
        )}

        {isLoading ? (
          <Spinner label="Loading audit history..." size="lg" />
        ) : entries.length === 0 ? (
          <EmptyState
            title="No Audit Records Found"
            description="No actions match the selected audit query filters."
            action={
              <Button size="sm" variant="secondary" onClick={handleResetFilters}>
                Clear Filter
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px] font-sans">
                <tr>
                  <th className="px-4 py-3 font-semibold">Timestamp</th>
                  <th className="px-4 py-3 font-semibold">Actor</th>
                  <th className="px-4 py-3 font-semibold">Action</th>
                  <th className="px-4 py-3 font-semibold">Target Type</th>
                  <th className="px-4 py-3 font-semibold">Target ID</th>
                  <th className="px-4 py-3 font-semibold text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {entries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedEntry(entry)}
                  >
                    <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200 font-sans">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span>{entry.actor}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-cyan-300 font-bold font-sans">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-[11px]">
                        {entry.action}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300 font-sans">{entry.target_type}</td>
                    <td className="px-4 py-2.5 text-slate-400">
                      {entry.target_id || <span className="text-slate-600">-</span>}
                    </td>
                    <td className="px-4 py-2.5 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEntry(entry);
                        }}
                        className="p-1 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800"
                        title="View Audit Details"
                        aria-label={`View audit entry ${entry.id}`}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
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

      {/* Audit Detail Modal */}
      <Modal
        isOpen={selectedEntry !== null}
        onClose={() => setSelectedEntry(null)}
        title="Audit Record Detail"
        description={`Record #${selectedEntry?.id} · ${selectedEntry?.action}`}
        footer={
          <Button size="sm" variant="secondary" onClick={() => setSelectedEntry(null)}>
            Close
          </Button>
        }
      >
        {selectedEntry && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block font-sans">Actor</span>
                <span className="text-slate-200">{selectedEntry.actor}</span>
              </div>
              <div>
                <span className="text-slate-500 block font-sans">Action</span>
                <span className="text-cyan-400 font-bold">{selectedEntry.action}</span>
              </div>
              <div>
                <span className="text-slate-500 block font-sans">Target Type</span>
                <span className="text-slate-200">{selectedEntry.target_type}</span>
              </div>
              <div>
                <span className="text-slate-500 block font-sans">Target ID</span>
                <span className="text-slate-200">{selectedEntry.target_id || 'N/A'}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 block font-sans">Timestamp</span>
                <span className="text-slate-300">{selectedEntry.timestamp}</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Audit Event Payload (JSON)
              </h4>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-56">
                {JSON.stringify(selectedEntry.details, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
