import React from 'react';

interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  headerAction?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  headerAction,
  children,
  footer,
  className = '',
  bodyClassName = '',
}) => {
  return (
    <div className={`bg-slate-900/90 border border-slate-800 rounded-lg shadow-md overflow-hidden ${className}`}>
      {(title || subtitle || headerAction) && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800/80 bg-slate-900/50">
          <div>
            {title && (
              <h2 className="text-sm font-semibold tracking-wide text-slate-100 flex items-center gap-2">
                {title}
              </h2>
            )}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className={`p-5 ${bodyClassName}`}>{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-slate-800/80 bg-slate-950/40 text-xs text-slate-400">
          {footer}
        </div>
      )}
    </div>
  );
};

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  icon?: React.ReactNode;
  subtext?: string;
  trend?: 'up' | 'down' | 'neutral';
  tone?: 'default' | 'danger' | 'warning' | 'success';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  icon,
  subtext,
  tone = 'default',
}) => {
  const tones = {
    default: 'text-slate-100',
    danger: 'text-red-400',
    warning: 'text-amber-400',
    success: 'text-emerald-400',
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 shadow-sm hover:border-slate-700 transition-colors">
      <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
        <span>{label}</span>
        {icon && <span className="text-slate-400">{icon}</span>}
      </div>
      <div className={`text-2xl font-bold mt-2 tracking-tight ${tones[tone]}`}>
        {value}
      </div>
      {subtext && <div className="text-xs text-slate-400 mt-1">{subtext}</div>}
    </div>
  );
};
