import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts';
import type { TimeSeriesBucket } from '../../types';

interface ActivityChartProps {
  data: TimeSeriesBucket[];
  isLoading?: boolean;
}

export const ActivityChart: React.FC<ActivityChartProps> = ({ data, isLoading = false }) => {
  if (isLoading) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        Loading activity data...
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        No observation activity in the selected range
      </div>
    );
  }

  const chartData = data.map((b) => {
    const d = new Date(b.timestamp);
    const label = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return {
      time: label,
      Events: b.event_count,
      Alerts: b.alert_count,
    };
  });

  return (
    <div className="h-64 w-full" aria-label="Observed network events and alerts over time">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#64748B"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#334155' }}
          />
          <YAxis
            stroke="#64748B"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#334155' }}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0F172A',
              borderColor: '#334155',
              borderRadius: '0.375rem',
              color: '#F8FAFC',
              fontSize: '12px',
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
          />
          <Bar dataKey="Events" fill="#0EA5E9" radius={[4, 4, 0, 0]} maxBarSize={32} />
          <Bar dataKey="Alerts" fill="#EF4444" radius={[4, 4, 0, 0]} maxBarSize={32} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
