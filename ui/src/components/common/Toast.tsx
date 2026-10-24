import React from 'react';
import { CheckCircle2, AlertTriangle, X, Info } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
}

interface ToastProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((toast) => {
        const isSuccess = toast.type === 'success';
        const isError = toast.type === 'error';

        const bg = isSuccess
          ? 'bg-emerald-950/90 border-emerald-700/60 text-emerald-200'
          : isError
          ? 'bg-red-950/90 border-red-700/60 text-red-200'
          : 'bg-slate-900/90 border-slate-700 text-slate-200';

        const icon = isSuccess ? (
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        ) : isError ? (
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
        ) : (
          <Info className="w-4 h-4 text-cyan-400 shrink-0" />
        );

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-center justify-between p-3 rounded-lg border shadow-lg backdrop-blur-xs text-xs font-medium animate-in slide-in-from-bottom-2 ${bg}`}
            role="alert"
          >
            <div className="flex items-center gap-2.5">
              {icon}
              <span>{toast.message}</span>
            </div>
            <button
              onClick={() => onDismiss(toast.id)}
              className="p-1 hover:opacity-75 focus:outline-none"
              aria-label="Dismiss alert"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
