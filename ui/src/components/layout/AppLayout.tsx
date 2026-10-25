import React from 'react';
import { Sidebar, type NavPage } from './Sidebar';
import { Header } from './Header';
import { ToastContainer, type ToastMessage } from '../common/Toast';
import type { SystemStatus } from '../../types';

interface AppLayoutProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  status: SystemStatus | null;
  isRefreshing: boolean;
  onRefresh: () => void;
  pageTitle: string;
  pageSubtitle?: string;
  headerAction?: React.ReactNode;
  toasts: ToastMessage[];
  onDismissToast: (id: string) => void;
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  currentPage,
  onNavigate,
  status,
  isRefreshing,
  onRefresh,
  pageTitle,
  pageSubtitle,
  headerAction,
  toasts,
  onDismissToast,
  children,
}) => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100">
      {/* Persistent Left Sidebar */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={onNavigate}
        isDemoMode={status?.is_demo_mode ?? false}
        appVersion={status?.app_version ?? '1.0.0'}
      />

      {/* Main Content Area */}
      <div className="flex flex-col flex-1 min-w-0 h-screen overflow-hidden">
        <Header
          title={pageTitle}
          subtitle={pageSubtitle}
          status={status}
          isRefreshing={isRefreshing}
          onRefresh={onRefresh}
          headerAction={headerAction}
        />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {children}
        </main>
      </div>

      {/* Persistent Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={onDismissToast} />
    </div>
  );
};
