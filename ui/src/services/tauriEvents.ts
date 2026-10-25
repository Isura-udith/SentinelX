/**
 * Backend event subscription helper using Tauri IPC events.
 */

import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { isTauriEnvironment } from './tauriCommands';

export const BACKEND_EVENTS = {
  NEW_EVENT: 'telemetry-cycle',
  NEW_ALERT: 'alert-detected',
  ALERT_STATUS_CHANGED: 'alert-status-changed',
  COLLECTOR_STATE_CHANGED: 'collector-state-changed',
} as const;

export async function subscribeToBackendEvent<T>(
  eventName: string,
  handler: (payload: T) => void,
): Promise<UnlistenFn> {
  if (isTauriEnvironment()) {
    try {
      return await listen<T>(eventName, (event) => handler(event.payload));
    } catch (err) {
      console.warn(`Failed to listen to Tauri event ${eventName}:`, err);
    }
  }

  // Fallback no-op unlisten for non-Tauri / test environments
  return () => {};
}
