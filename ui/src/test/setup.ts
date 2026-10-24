import '@testing-library/jest-dom/vitest';

// Polyfill ResizeObserver for Recharts in jsdom
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
