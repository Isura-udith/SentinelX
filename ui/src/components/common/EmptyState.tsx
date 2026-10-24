import React from 'react';
import { Database } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon = <Database className="w-10 h-10 text-slate-600" />,
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center border border-dashed border-slate-800 rounded-lg bg-slate-900/40 my-4">
      <div className="p-3 bg-slate-800/60 rounded-full mb-3">{icon}</div>
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <p className="text-xs text-slate-400 mt-1 max-w-sm">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};
