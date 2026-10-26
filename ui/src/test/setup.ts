import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';
import { getTestFixtureResponse } from './testFixtures';

// Polyfill ResizeObserver for Recharts in jsdom
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Mock Tauri core API for test harness
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn((command: string, args?: Record<string, unknown>) => {
    return Promise.resolve(getTestFixtureResponse(command, args || {}));
  }),
  isTauri: vi.fn(() => true),
}));

// Mock Tauri event API for test harness
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// Provide Tauri internal property marker so isTauriEnvironment() resolves true in test suite
// @ts-expect-error test harness mock
globalThis.__TAURI_INTERNALS__ = {
  invoke: vi.fn((command: string, args?: Record<string, unknown>) => {
    return Promise.resolve(getTestFixtureResponse(command, args || {}));
  }),
};
