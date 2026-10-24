import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Filter,
  X,
  RefreshCw,
  Eye,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Pagination } from '../components/common/Pagination';
import { Spinner } from '../components/common/Spinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { tauriCommands } from '../services/tauriCommands';
import type {
  NetworkEventSummary,
  NetworkEventDetails,
  EventQueryParams,
} from '../types';

export const EventsPage: React.FC = () => {
  const [events, setEvents] = useState<NetworkEventSummary[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filters state
  const [searchText, setSearchText] = useState<string>('');
  const [protocol, setProtocol] = useState<string>('');
  const [sourceIp, setSourceIp] = useState<string>('');
  const [destinationIp, setDestinationIp] = useState<string>('');
  const [destinationPort, setDestinationPort] = useState<string>('');
  const [telemetrySource, setTelemetrySource] = useState<string>('');

  // Pagination state
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);
  const [sortDesc, setSortDesc] = useState<boolean>(true);

  // Detail Modal state
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [eventDetails, setEventDetails] = useState<NetworkEventDetails | null>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState<boolean>(false);

  const fetchEvents = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const params: EventQueryParams = {
      limit,
      offset,
      sort_desc: sortDesc,
    };

    if (searchText.trim()) params.search_text = searchText.trim();
    if (protocol) params.protocol = protocol;
    if (sourceIp.trim()) params.source_ip = sourceIp.trim();
    if (destinationIp.trim()) params.destination_ip = destinationIp.trim();
    if (destinationPort.trim()) {
      const p = parseInt(destinationPort.trim(), 10);
      if (!isNaN(p) && p > 0 && p <= 65535) {
        params.destination_port = p;
      }
    }
    if (telemetrySource) params.telemetry_source = telemetrySource;

    try {
      const res = await tauriCommands.queryNetworkEvents(params);
      setEvents(res.items);
      setTotalCount(res.total_count);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, sortDesc, searchText, protocol, sourceIp, destinationIp, destinationPort, telemetrySource]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const handleOpenDetails = async (id: string) => {
    setSelectedEventId(id);
    setIsLoadingDetails(true);
    setEventDetails(null);
    try {
      const d = await tauriCommands.getNetworkEventDetails(id);
      setEventDetails(d);
    } catch (err) {
      console.error('Failed to load event details:', err);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  const handleResetFilters = () => {
    setSearchText('');
    setProtocol('');
    setSourceIp('');
    setDestinationIp('');
    setDestinationPort('');
    setTelemetrySource('');
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
      {/* Search & Filters Bar */}
      <Card bodyClassName="p-4">
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-3">
            {/* Full text search */}
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search by IP, port, protocol, PID..."
                value={searchText}
                onChange={(e) => {
                  setSearchText(e.target.value);
                  setOffset(0);
                }}
                className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>

            {/* Protocol */}
            <select
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value);
                setOffset(0);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              aria-label="Filter by protocol"
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>

            {/* Source filter */}
            <select
              value={telemetrySource}
              onChange={(e) => {
                setTelemetrySource(e.target.value);
                setOffset(0);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              aria-label="Filter by telemetry source"
            >
              <option value="">All Sources</option>
              <option value="WindowsTcp">WindowsTcp</option>
              <option value="Mock">Mock</option>
            </select>

            {/* Sort toggle */}
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                setSortDesc(!sortDesc);
                setOffset(0);
              }}
            >
              {sortDesc ? 'Newest First' : 'Oldest First'}
            </Button>

            {/* Reset */}
            {(searchText || protocol || sourceIp || destinationIp || destinationPort || telemetrySource) && (
              <Button size="sm" variant="ghost" onClick={handleResetFilters} leftIcon={<X className="w-3.5 h-3.5" />}>
                Reset
              </Button>
            )}

            <Button
              size="sm"
              variant="secondary"
              onClick={fetchEvents}
              isLoading={isLoading}
              leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              Apply
            </Button>
          </div>

          {/* Secondary Filter Inputs */}
          <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800/60 text-xs">
            <span className="text-slate-500 font-medium flex items-center gap-1">
              <Filter className="w-3.5 h-3.5" /> Advanced:
            </span>

            <input
              type="text"
              placeholder="Source IP (e.g. 192.168.1.100)"
              value={sourceIp}
              onChange={(e) => {
                setSourceIp(e.target.value);
                setOffset(0);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 w-48 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />

            <input
              type="text"
              placeholder="Dest IP"
              value={destinationIp}
              onChange={(e) => {
                setDestinationIp(e.target.value);
                setOffset(0);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 w-40 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />

            <input
              type="number"
              placeholder="Dest Port (1-65535)"
              value={destinationPort}
              onChange={(e) => {
                setDestinationPort(e.target.value);
                setOffset(0);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 w-36 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>
        </div>
      </Card>

      {/* Events Table */}
      <Card bodyClassName="p-0 overflow-hidden">
        {errorMessage && (
          <div className="p-4 bg-red-950/60 border-b border-red-800/60 text-xs text-red-200">
            Error loading events: {errorMessage}
          </div>
        )}

        {isLoading ? (
          <Spinner label="Querying event repository..." size="lg" />
        ) : events.length === 0 ? (
          <EmptyState
            title="No Matching Events Found"
            description="No network connection records match your current filter parameters."
            action={
              <Button size="sm" variant="secondary" onClick={handleResetFilters}>
                Clear Filters
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="px-4 py-3 font-semibold">Timestamp (Local)</th>
                  <th className="px-4 py-3 font-semibold">Source</th>
                  <th className="px-4 py-3 font-semibold">Proto</th>
                  <th className="px-4 py-3 font-semibold">Source Address : Port</th>
                  <th className="px-4 py-3 font-semibold">Destination Address : Port</th>
                  <th className="px-4 py-3 font-semibold">Process ID</th>
                  <th className="px-4 py-3 font-semibold text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 font-mono">
                {events.map((evt) => (
                  <tr
                    key={evt.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => handleOpenDetails(evt.id)}
                  >
                    <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">
                      {formatTimestamp(evt.timestamp)}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 font-sans">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                        {evt.telemetry_source}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-cyan-400 font-bold font-sans">
                      {evt.protocol}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200">
                      {evt.source_ip}:{evt.source_port}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200 font-semibold">
                      {evt.destination_ip}:{evt.destination_port}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">
                      {evt.process_id != null ? (
                        <span className="text-cyan-300 font-bold">{evt.process_id}</span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenDetails(evt.id);
                        }}
                        className="p-1 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                        title="View Event Details"
                        aria-label={`View details for event ${evt.id}`}
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

      {/* Event Details Modal */}
      <Modal
        isOpen={selectedEventId !== null}
        onClose={() => setSelectedEventId(null)}
        title="Normalized Event Record"
        description={`Event ID: ${selectedEventId}`}
        size="lg"
        footer={
          <Button size="sm" variant="secondary" onClick={() => setSelectedEventId(null)}>
            Close
          </Button>
        }
      >
        {isLoadingDetails ? (
          <Spinner label="Loading event record from SQLite..." size="md" />
        ) : eventDetails ? (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block">Protocol</span>
                <span className="text-cyan-400 font-bold">{eventDetails.protocol}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Telemetry Source</span>
                <span className="text-slate-200">{eventDetails.telemetry_source}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Source IP : Port</span>
                <span className="text-slate-200">
                  {eventDetails.source_ip}:{eventDetails.source_port}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Destination IP : Port</span>
                <span className="text-slate-100 font-bold">
                  {eventDetails.destination_ip}:{eventDetails.destination_port}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Process ID</span>
                <span className="text-slate-200">
                  {eventDetails.process_id != null ? eventDetails.process_id : 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Socket State</span>
                <span className="text-slate-200">{eventDetails.socket_state}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 block">Observed Timestamp</span>
                <span className="text-slate-300">{eventDetails.timestamp}</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Validated Metadata & Context
              </h4>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                {JSON.stringify(eventDetails.metadata, null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <div className="p-4 text-center text-slate-400 text-xs">
            Failed to retrieve event details.
          </div>
        )}
      </Modal>
    </div>
  );
};
