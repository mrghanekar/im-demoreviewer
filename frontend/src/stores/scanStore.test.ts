/**
 * Regression tests for the scan stream lifecycle.
 *
 * Every bug covered here was silent in the UI: the scan still finished and
 * findings still appeared, just seconds late via polling or attributed to the
 * wrong scan. That is exactly the class of defect a build+lint pass can't
 * catch, so it gets tests.
 */

import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/api', () => ({
  createScan: vi.fn(),
  fetchScan: vi.fn(async () => ({ id: 'scan-a', status: 'running', summary: {} })),
  fetchFindings: vi.fn(async () => []),
  fetchScans: vi.fn(async () => []),
  cancelScan: vi.fn(),
  suppressFinding: vi.fn(),
  unsuppressFinding: vi.fn(),
}));

vi.mock('@/lib/sound', () => ({ playSuccessSound: vi.fn() }));

import * as api from '@/lib/api';
import { useScanStore } from '@/stores/scanStore';
import type { Finding, Scan, ScanEvent } from '@/lib/types';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const sockets: FakeWebSocket[] = [];

class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readyState = FakeWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;

  url: string;

  constructor(url: string) {
    this.url = url;
    sockets.push(this);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.();
  }

  /** Deliver a server event as if it arrived over the wire. */
  deliver(event: ScanEvent) {
    this.onmessage?.({ data: JSON.stringify(event) });
  }
}

function findingEvent(id: string, severity: string): ScanEvent {
  return {
    event_type: 'finding_discovered',
    scan_id: 'scan-a',
    timestamp: '2026-01-01T00:00:00Z',
    data: { id, title: `finding ${id}`, severity },
  } as unknown as ScanEvent;
}

function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: 'scan-a',
    status: 'running',
    check_executions: [],
    findings: [],
    summary: { total_findings: 0, by_severity: {}, checks_passed: 0, checks_failed: 0, checks_errored: 0 },
    ...overrides,
  } as unknown as Scan;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeEach(() => {
  sockets.length = 0;
  vi.clearAllMocks();
  vi.stubGlobal('WebSocket', FakeWebSocket);
  vi.stubGlobal('window', { location: { protocol: 'http:', host: 'app.example.com' } });
  useScanStore.getState().reset();
});

afterEach(() => {
  useScanStore.getState().reset();
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------

describe('connectWebSocket authentication', () => {
  it('falls back to the stored token when the caller does not pass one', () => {
    useScanStore.setState({ scanToken: 'tok-123' });

    useScanStore.getState().connectWebSocket('scan-a');

    expect(sockets).toHaveLength(1);
    expect(sockets[0].url).toContain('token=tok-123');
  });

  it('remembers a token passed explicitly so later reconnects stay authenticated', () => {
    useScanStore.getState().connectWebSocket('scan-a', 'tok-abc');
    expect(useScanStore.getState().scanToken).toBe('tok-abc');
  });

  it('polls instead of opening a socket the server would reject with 4003', () => {
    useScanStore.getState().connectWebSocket('scan-a');

    expect(sockets).toHaveLength(0);
    expect(useScanStore.getState().socket).toBeNull();
    expect(useScanStore.getState()._pollTimer).not.toBeNull();
  });

  it('stops the fallback poll once a real stream opens', () => {
    useScanStore.getState().startPollingFallback('scan-a');
    expect(useScanStore.getState()._pollTimer).not.toBeNull();

    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');
    sockets[0].onopen?.();

    expect(useScanStore.getState()._pollTimer).toBeNull();
  });
});

describe('connectWebSocket idempotence', () => {
  it('does not tear down a healthy socket for the same scan', () => {
    const store = useScanStore.getState();
    store.connectWebSocket('scan-a', 'tok-123');
    store.connectWebSocket('scan-a', 'tok-123');

    expect(sockets).toHaveLength(1);
    expect(sockets[0].readyState).toBe(FakeWebSocket.OPEN);
  });

  it('replaces the socket when the scan changes', () => {
    const store = useScanStore.getState();
    store.connectWebSocket('scan-a', 'tok-123');
    store.connectWebSocket('scan-b', 'tok-123');

    expect(sockets).toHaveLength(2);
    expect(sockets[0].readyState).toBe(FakeWebSocket.CLOSED);
    expect(useScanStore.getState().socket).toBe(sockets[1]);
  });

  it('an intentional disconnect does not start the poll fallback', () => {
    useScanStore.setState({ isScanning: true, currentScanId: 'scan-a' });
    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');

    useScanStore.getState().disconnectWebSocket();

    expect(useScanStore.getState().socket).toBeNull();
    expect(useScanStore.getState()._pollTimer).toBeNull();
  });

  it('a real dropped connection does start the poll fallback', () => {
    useScanStore.setState({ isScanning: true, currentScanId: 'scan-a' });
    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');

    // Server hangs up on its own — no store bookkeeping preceded it.
    sockets[0].onclose?.();

    expect(useScanStore.getState().socket).toBeNull();
    expect(useScanStore.getState()._pollTimer).not.toBeNull();
  });

  it('a superseded socket closing does not clear the live one', () => {
    const store = useScanStore.getState();
    useScanStore.setState({ isScanning: true, currentScanId: 'scan-b' });
    store.connectWebSocket('scan-a', 'tok-123');
    store.connectWebSocket('scan-b', 'tok-123');

    // The replaced socket's onclose already fired during the swap; fire it
    // again the way a real socket does when the server hangs up late.
    sockets[0].onclose?.();

    expect(useScanStore.getState().socket).toBe(sockets[1]);
    expect(useScanStore.getState()._pollTimer).toBeNull();
  });
});

describe('finding batching', () => {
  it('flushes queued findings into the store and updates the severity summary', async () => {
    useScanStore.setState({ currentScan: makeScan() });
    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');

    sockets[0].deliver(findingEvent('f1', 'critical'));
    sockets[0].deliver(findingEvent('f2', 'critical'));
    sockets[0].deliver(findingEvent('f3', 'high'));

    // Nothing lands until the 150ms batch window closes.
    expect(useScanStore.getState().findings).toHaveLength(0);
    await sleep(220);

    const state = useScanStore.getState();
    expect(state.findings.map((f: Finding) => f.id)).toEqual(['f1', 'f2', 'f3']);
    expect(state.currentScan?.summary.total_findings).toBe(3);
    expect(state.currentScan?.summary.by_severity).toMatchObject({ critical: 2, high: 1 });
  });

  it('survives a scan whose summary has not been populated yet', async () => {
    useScanStore.setState({ currentScan: { id: 'scan-a', status: 'running' } as unknown as Scan });
    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');

    sockets[0].deliver(findingEvent('f1', 'high'));
    await sleep(220);

    const state = useScanStore.getState();
    expect(state.findings).toHaveLength(1);
    expect(state.currentScan?.summary.by_severity).toMatchObject({ high: 1 });
  });

  it('reset drops a pending batch so it cannot land on the next scan', async () => {
    useScanStore.setState({ currentScan: makeScan() });
    useScanStore.getState().connectWebSocket('scan-a', 'tok-123');
    sockets[0].deliver(findingEvent('f1', 'high'));

    useScanStore.getState().reset();
    await sleep(220);

    expect(useScanStore.getState().findings).toHaveLength(0);
    expect(useScanStore.getState().scanToken).toBeNull();
  });
});

describe('loadFindings scan attribution', () => {
  it('ignores a response for a scan the user has already navigated away from', async () => {
    const stale: Finding[] = [{ id: 'stale-1' } as Finding];
    vi.mocked(api.fetchFindings).mockResolvedValueOnce(stale);

    useScanStore.setState({ currentScanId: 'scan-b', findings: [], findingsScanId: 'scan-b' });
    await useScanStore.getState().loadFindings('scan-a');

    expect(useScanStore.getState().findings).toHaveLength(0);
    expect(useScanStore.getState().findingsScanId).toBe('scan-b');
  });

  it('accepts a response for the scan currently being viewed', async () => {
    const fresh: Finding[] = [{ id: 'fresh-1' } as Finding];
    vi.mocked(api.fetchFindings).mockResolvedValueOnce(fresh);

    useScanStore.setState({ currentScanId: 'scan-a' });
    await useScanStore.getState().loadFindings('scan-a');

    expect(useScanStore.getState().findings.map((f) => f.id)).toEqual(['fresh-1']);
    expect(useScanStore.getState().findingsScanId).toBe('scan-a');
  });
});
