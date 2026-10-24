import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';

describe('SentinelX Desktop Frontend Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders application branding and header status bar', async () => {
    render(<App />);

    expect(screen.getByText(/SENTINEL/i)).toBeInTheDocument();
    expect(screen.getByText(/SOC Threat Defense/i)).toBeInTheDocument();

    // Verify global navigation tabs are present
    expect(screen.getByRole('button', { name: /Overview/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Network Events/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Security Alerts/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Detection Rules/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Telemetry/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Audit History/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Settings/i })).toBeInTheDocument();

    // Verify backend operational status
    await waitFor(() => {
      expect(screen.getByText(/Collector Running/i)).toBeInTheDocument();
      expect(screen.getByText(/SQLite Ready/i)).toBeInTheDocument();
    });
  });

  it('navigates to Network Events page and displays paginated event data', async () => {
    render(<App />);

    const eventsNav = screen.getByRole('button', { name: /Network Events/i });
    fireEvent.click(eventsNav);

    await waitFor(() => {
      expect(screen.getByText(/Normalized Network Events/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/Search by IP, port/i)).toBeInTheDocument();
    });
  });

  it('navigates to Security Alerts page and supports acknowledge dialog', async () => {
    render(<App />);

    const alertsNav = screen.getByRole('button', { name: /Security Alerts/i });
    fireEvent.click(alertsNav);

    await waitFor(() => {
      expect(screen.getByText(/Security Threat Alerts/i)).toBeInTheDocument();
    });

    // Find and click Acknowledge button
    const ackButtons = await screen.findAllByRole('button', { name: /^Acknowledge$/i });
    expect(ackButtons.length).toBeGreaterThan(0);
    fireEvent.click(ackButtons[0]);

    // Modal should appear
    await waitFor(() => {
      expect(screen.getByText(/Acknowledge Security Alert/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/Add investigation context/i)).toBeInTheDocument();
    });
  });

  it('navigates to Detection Rules page and validates invalid threshold inputs', async () => {
    render(<App />);

    const rulesNav = screen.getByRole('button', { name: /Detection Rules/i });
    fireEvent.click(rulesNav);

    await waitFor(() => {
      expect(screen.getByText(/Detection Rules & Heuristics/i)).toBeInTheDocument();
      expect(screen.getByText(/NET-001/i)).toBeInTheDocument();
    });

    // Open edit modal
    const editButtons = screen.getAllByRole('button', { name: /Edit Config/i });
    fireEvent.click(editButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/Edit Rule Configuration/i)).toBeInTheDocument();
    });

    // Input invalid zero threshold
    const thresholdInput = screen.getByDisplayValue('10');
    fireEvent.change(thresholdInput, { target: { value: '0' } });

    const saveButton = screen.getByRole('button', { name: /Save Changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByText(/Threshold must be a valid positive integer/i)).toBeInTheDocument();
    });
  });

  it('navigates to Telemetry page and renders collector health metrics', async () => {
    render(<App />);

    const telemetryNav = screen.getByRole('button', { name: /^Telemetry$/i });
    fireEvent.click(telemetryNav);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Telemetry Collection Service/i })).toBeInTheDocument();
      expect(screen.getByText(/Windows TCP Snapshot Collector/i)).toBeInTheDocument();
    });
  });

  it('navigates to Audit History page and displays immutable records', async () => {
    render(<App />);

    const auditNav = screen.getByRole('button', { name: /Audit History/i });
    fireEvent.click(auditNav);

    await waitFor(() => {
      expect(screen.getByText(/Compliance Audit Trail/i)).toBeInTheDocument();
      expect(screen.getByText(/Audit Trail \(Read-Only\)/i)).toBeInTheDocument();
    });
  });

  it('navigates to Settings page and displays retention warnings and database location', async () => {
    render(<App />);

    const settingsNav = screen.getByRole('button', { name: /Settings/i });
    fireEvent.click(settingsNav);

    await waitFor(() => {
      expect(screen.getByText(/Application Settings/i)).toBeInTheDocument();
      expect(screen.getByText(/Evidence Preservation Rule/i)).toBeInTheDocument();
      expect(screen.getByText(/Demonstration \/ Mock Mode/i)).toBeInTheDocument();
    });
  });
});
