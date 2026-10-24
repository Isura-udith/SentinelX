import React from 'react';
import { Loader2 } from 'lucide-react';

interface SpinnerProps {
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const Spinner: React.FC<SpinnerProps> = ({ label = 'Loading...', size = 'md' }) => {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  return (
    <div className="flex flex-col items-center justify-center gap-2 py-8 text-slate-400" role="status">
      <Loader2 className={`${sizes[size]} animate-spin text-cyan-500`} aria-hidden="true" />
      {label && <span className="text-xs font-medium tracking-wide">{label}</span>}
      <span className="sr-only">{label}</span>
    </div>
  );
};
