/**
 * Zustand store for scan state management.
 */

import { create } from 'zustand';
import type { Scan, ScanRequest, ServiceCategory, Finding, ScanEvent, CheckExecution, Severity, CheckStatus, ScanSummary } from '@/lib/types';
import * as api from '@/lib/api';
import { playSuccessSound } from '@/lib/sound';
import { useToastStore } from '@/stores/toastStore';

interface LogEntry {
  timestamp: string;
  message: string;
  type: 'info' | 'success' | 'error' | 'warning';
}

// Findings arrive in bursts and are flushed to the store every 150ms. The
// buffer lives outside the store because it isn't reactive data — nothing
// renders it — and mutating it through `state._pendingFindings.push()` was a
// write to store state that bypassed set(), which Zustand does not support.
let pendingFindings: Finding[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;

interface ScanState {
  // Wizard state
  scope: 'org' | 'project';
  targetId: string;
  selectedCategories: ServiceCategory[];
  selectedProjects: string[];

  // Active scan
  currentScanId: string | null;
  currentScan: Scan | null;
  findings: Finding[];
  scanLogs: LogEntry[];
  isScanning: boolean;
  isFetchingFindings: boolean;
  scanError: string | null;

  // Scan history
  scans: Scan[];

  // WebSocket
  socket: WebSocket | null;
  // Access token for the active scan's stream. The backend closes tokenless
  // sockets with 4003, so this has to survive navigation to the results page.
  scanToken: string | null;
  // Which scan `findings` belongs to, so a slow in-flight fetch for scan A
  // can't land after the user has already opened scan B.
  findingsScanId: string | null;

  // Polling fallback
  _pollTimer: ReturnType<typeof setInterval> | null;

  // Actions
  setScope: (scope: 'org' | 'project') => void;
  setTargetId: (id: string) => void;
  setCategories: (categories: ServiceCategory[]) => void;
  setSelectedProjects: (projects: string[]) => void;
  startScan: () => Promise<void>;
  connectWebSocket: (scanId: string, token?: string) => void;
  disconnectWebSocket: () => void;
  startPollingFallback: (scanId: string) => void;
  stopPollingFallback: () => void;
  pollScan: (scanId: string) => Promise<void>;
  cancelScan: () => Promise<void>;
  loadFindings: (scanId: string) => Promise<void>;
  loadScans: () => Promise<void>;
  toggleSuppressFinding: (scanId: string, findingId: string, reason?: string) => Promise<void>;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set, get) => ({
  // Initial state
  scope: 'project',
  targetId: '',
  selectedCategories: [
    'gke', 'gce', 'gcs', 'databases', 'security',
    'networking', 'iam', 'data', 'monitoring', 'billing', 'vertex_ai',
    'cloud_run', 'cloud_functions', 'secret_manager', 'cloud_build',
    'memorystore', 'firestore', 'spanner', 'iap', 'composer', 'posture',
    'alloydb', 'app_engine', 'cloud_run_jobs',
    'api_security', 'artifact_registry', 'patch_management', 'compliance',
  ],
  selectedProjects: [],
  currentScanId: null,
  currentScan: null,
  findings: [],
  scanLogs: [],
  isScanning: false,
  isFetchingFindings: false,
  scanError: null,
  scans: [],
  socket: null,
  scanToken: null,
  findingsScanId: null,
  _pollTimer: null,

  // Actions
  setScope: (scope) => set({ scope }),
  setTargetId: (targetId) => set({ targetId }),
  setCategories: (selectedCategories) => set({ selectedCategories }),
  setSelectedProjects: (selectedProjects) => set({ selectedProjects }),

  startScan: async () => {
    const { scope, targetId, selectedCategories, selectedProjects } = get();
    set({ isScanning: true, scanError: null, scanLogs: [], findings: [] });

    try {
      const request: ScanRequest = {
        scope,
        target_id: targetId,
        categories: selectedCategories,
        specific_projects: scope === 'org' && selectedProjects.length > 0 ? selectedProjects : undefined,
      };

      const scan = await api.createScan(request);
      set({
        currentScanId: scan.id,
        currentScan: scan,
        scanToken: scan.scan_token ?? null,
        findings: [],
        findingsScanId: scan.id,
      });

      // Connect to WebSocket for real-time updates
      get().connectWebSocket(scan.id, scan.scan_token);

    } catch (error) {
      set({
        isScanning: false,
        scanError: error instanceof Error ? error.message : 'Failed to start scan',
      });
    }
  },

  connectWebSocket: (scanId: string, token?: string) => {
    // Callers that don't hold the token (the results page mounting on a scan
    // started elsewhere in the app) fall back to the stored one. Passing no
    // token opened a socket the backend immediately closed with 4003, and
    // because it replaced the authenticated socket, every scan silently
    // degraded to 3-second polling.
    const accessToken = token ?? get().scanToken ?? undefined;
    if (token) set({ scanToken: token });

    const { socket } = get();
    if (socket && socket.readyState !== WebSocket.CLOSED) {
      // Already streaming this scan — don't tear down a healthy connection.
      if (socket.url.includes(`/scans/${scanId}/stream`)) return;
      // Detach before closing: a deliberate swap must not look like a dropped
      // connection to the onclose handler, or it starts the poll fallback for
      // a stream we are about to replace.
      set({ socket: null });
      socket.close();
    }

    if (!accessToken) {
      // No token means the server will reject the socket. Say so once and use
      // polling rather than looping through a doomed connect.
      console.warn('No scan access token — using polling instead of WebSocket');
      set({ socket: null });
      get().startPollingFallback(scanId);
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Handle both dev (proxy) and prod (same origin)
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/scans/${scanId}/stream?token=${encodeURIComponent(accessToken)}`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('WebSocket connected');
      // A live stream supersedes any fallback polling started earlier.
      get().stopPollingFallback();
    };

    ws.onmessage = (event) => {
      try {
        const message: ScanEvent = JSON.parse(event.data);
        handleScanEvent(message, set, get);
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    };

    ws.onclose = () => {
      // A socket we already replaced still fires onclose. Without this guard
      // the old socket nulls out the *new* one and starts a phantom poll loop.
      if (get().socket !== ws) return;

      console.log('WebSocket disconnected');
      set({ socket: null });
      // Fallback: if still scanning when WS closes, start polling
      const { isScanning, currentScanId } = get();
      if (isScanning && currentScanId) {
        console.log('WebSocket closed while scanning — starting poll fallback');
        get().startPollingFallback(currentScanId);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    set({ socket: ws });
  },

  disconnectWebSocket: () => {
    const { socket } = get();
    if (socket) {
      // Detach first — see connectWebSocket. An intentional disconnect must
      // not be mistaken for a dropped stream and restart polling.
      set({ socket: null });
      socket.close();
    }
  },

  startPollingFallback: (scanId: string) => {
    // Don't start if already polling
    if (get()._pollTimer) return;

    // Throttle findings refresh: poll the scan summary every 3s, but only
    // pull the full findings list every 4th tick (~12s) and only if the
    // total count changed. Replacing the array on every tick re-renders
    // every FindingRow and collapses any expanded panels — see the matching
    // change in Results.tsx for the per-page interval.
    let tick = 0;
    let lastFindingCount = get().findings.length;
    const timer = setInterval(async () => {
      try {
        const scan = await api.fetchScan(scanId);
        set({ currentScan: scan });

        if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
          get().stopPollingFallback();
          set({ isScanning: false });
          // Always do a final pull when the scan terminates so the table
          // matches the persisted state.
          get().loadFindings(scanId);
          if (scan.status === 'completed') {
            playSuccessSound();
          }
          return;
        }
        // While running, only refresh the findings list when the summary's
        // total grew. Avoids gratuitous full-array replacement.
        tick += 1;
        const expected = scan.summary?.total_findings ?? 0;
        if (tick % 4 === 0 && expected !== lastFindingCount) {
          const findings = await api.fetchFindings(scanId, { includeSuppressed: true });
          set({ findings });
          lastFindingCount = findings.length;
        }
      } catch (error) {
        console.error('Poll fallback error:', error);
      }
    }, 3000);

    set({ _pollTimer: timer });
  },

  stopPollingFallback: () => {
    const timer = get()._pollTimer;
    if (timer) {
      clearInterval(timer);
      set({ _pollTimer: null });
    }
  },

  pollScan: async (scanId: string) => {
    // Keep for fallback or manual refresh
    try {
      const scan = await api.fetchScan(scanId);
      set({ currentScan: scan });

      if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
        set({ isScanning: false });
        get().disconnectWebSocket();
      }
    } catch (error) {
      console.error('Poll error:', error);
    }
  },

  cancelScan: async () => {
    const { currentScanId } = get();
    if (!currentScanId) return;

    try {
      await api.cancelScan(currentScanId);
      get().disconnectWebSocket();
      get().stopPollingFallback();
      set({ isScanning: false });
    } catch (error) {
      console.error('Cancel error:', error);
    }
  },

  loadFindings: async (scanId: string) => {
    set({ isFetchingFindings: true });
    try {
      // Include suppressed so the UI can render them dimmed and offer unsuppress.
      const findings = await api.fetchFindings(scanId, { includeSuppressed: true });
      // Opening scan B while A's fetch is in flight used to show A's findings
      // under B's header. Drop a response the user has already navigated away
      // from.
      if (get().currentScanId && get().currentScanId !== scanId) {
        set({ isFetchingFindings: false });
        return;
      }
      set({ findings, findingsScanId: scanId, isFetchingFindings: false });
    } catch (error) {
      console.error('Load findings error:', error);
      set({ isFetchingFindings: false });
    }
  },

  toggleSuppressFinding: async (scanId: string, findingId: string, reason: string = '') => {
    const current = get().findings.find((f) => f.id === findingId);
    if (!current) return;
    const wasSuppressed = current.suppressed;
    try {
      const updated = wasSuppressed
        ? await api.unsuppressFinding(scanId, findingId)
        : await api.suppressFinding(scanId, findingId, reason);
      set({
        findings: get().findings.map((f) => (f.id === findingId ? updated : f)),
      });
      // Toast with Undo — re-invoke this same action to flip back.
      useToastStore.getState().push({
        variant: 'success',
        message: wasSuppressed
          ? `Unsuppressed: ${current.title}`
          : `Suppressed: ${current.title}`,
        action: {
          label: 'Undo',
          onClick: () => {
            void get().toggleSuppressFinding(scanId, findingId);
          },
        },
      });
    } catch (error) {
      console.error('Toggle suppress error:', error);
      useToastStore.getState().push({
        variant: 'error',
        message: `Failed to ${wasSuppressed ? 'unsuppress' : 'suppress'} finding`,
      });
    }
  },

  loadScans: async () => {
    try {
      const scans = await api.fetchScans();
      set({ scans });
    } catch (error) {
      console.error('Load scans error:', error);
    }
  },

  reset: () => {
    get().disconnectWebSocket();
    get().stopPollingFallback();
    // The batch buffer outlives the store's state object; a stale flush after
    // reset would re-populate findings for a scan the user has left.
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null;
    pendingFindings = [];
    set({
      currentScanId: null,
      currentScan: null,
      findings: [],
      findingsScanId: null,
      scanToken: null,
      scanLogs: [],
      isScanning: false,
      scanError: null,
    });
  },
}));

function flushPendingFindings(
  set: (state: Partial<ScanState>) => void,
  get: () => ScanState,
) {
  flushTimer = null;
  const queued = pendingFindings;
  if (queued.length === 0) return;
  // Reset queue first so concurrent pushes during the spread go in the next batch.
  pendingFindings = [];

  const state = get();
  const merged = state.findings.concat(queued);
  const scan = state.currentScan;

  // Single summary recompute over the batch
  let newScan = scan;
  if (scan) {
    // A scan fetched before its summary was populated has no by_severity;
    // spreading undefined here threw and killed the whole findings stream.
    const bySeverity = { ...(scan.summary?.by_severity ?? {}) } as Record<Severity, number>;
    for (const f of queued) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }
    newScan = {
      ...scan,
      findings: merged,
      summary: {
        ...scan.summary,
        total_findings: (scan.summary?.total_findings ?? 0) + queued.length,
        by_severity: bySeverity,
      },
    };
  }

  set({ findings: merged, currentScan: newScan });
}

// Helper to process WebSocket events
function handleScanEvent(event: ScanEvent, set: (state: Partial<ScanState>) => void, get: () => ScanState) {
  const { currentScan, scanLogs } = get();
  const timestamp = new Date().toISOString();

  switch (event.event_type) {
    case 'check_started': {
      const checkId = event.data.check_id as string;
      const checkTitle = event.data.check_title as string;
      
      set({
        scanLogs: [
          ...scanLogs,
          { timestamp, message: `Started check: ${checkTitle} (${checkId})`, type: 'info' }
        ],
        // Update check execution status to running
        currentScan: currentScan ? {
          ...currentScan,
          check_executions: currentScan.check_executions.map((ce: CheckExecution) => 
            ce.check_id === checkId ? { ...ce, status: 'running', started_at: timestamp } : ce
          )
        } : currentScan
      });
      break;
    }

    case 'check_completed': {
      const status = event.data.status as CheckStatus;
      const findingsCount = event.data.findings_count as number;
      const durationMs = event.data.duration_ms as number;
      const errorMsg = event.data.error as string;
      const completedCheckId = event.data.check_id as string;

      const isError = status === 'errored';
      const isFailed = status === 'failed';
      const isPassed = status === 'passed';
      
      set({
        scanLogs: [
          ...scanLogs,
          { 
            timestamp, 
            message: `Completed check: ${completedCheckId} - ${status} (${findingsCount} findings)`, 
            type: isError ? 'error' : (isFailed ? 'warning' : 'success') 
          }
        ],
        // Update check execution status AND summary counts
        currentScan: currentScan ? {
          ...currentScan,
          check_executions: currentScan.check_executions.map((ce: CheckExecution) => 
            ce.check_id === completedCheckId ? { 
              ...ce, 
              status: status, 
              findings_count: findingsCount,
              duration_ms: durationMs,
              error_message: errorMsg,
              completed_at: timestamp
            } : ce
          ),
          summary: {
            ...currentScan.summary,
            checks_passed: currentScan.summary.checks_passed + (isPassed ? 1 : 0),
            checks_failed: currentScan.summary.checks_failed + (isFailed ? 1 : 0),
            checks_errored: currentScan.summary.checks_errored + (isError ? 1 : 0),
          }
        } : currentScan
      });
      break;
    }

    case 'finding_discovered': {
      const severity = event.data.severity as Severity;
      const title = event.data.title as string;
      const newFinding = event.data as unknown as Finding;

      // Log immediately so the activity stream stays responsive
      set({
        scanLogs: [
          ...scanLogs,
          { timestamp, message: `Finding found: ${title} (${severity})`, type: 'warning' }
        ],
      });

      // Batch finding-list updates: queue here and flush once per 150ms.
      // Avoids O(n²) re-spreads when 100+ findings arrive in quick succession.
      pendingFindings.push(newFinding);
      if (!flushTimer) {
        flushTimer = setTimeout(() => flushPendingFindings(set, get), 150);
      }
      break;
    }

    case 'scan_completed':
    case 'scan_failed':
    case 'scan_cancelled': {
      if (event.event_type === 'scan_completed') {
        playSuccessSound();
      }
      
      const newStatus = event.event_type.split('_')[1] as Scan['status'];
      const summaryUpdate = event.data as Partial<ScanSummary>;

      set({
        isScanning: false,
        scanLogs: [
          ...scanLogs,
          { timestamp, message: `Scan ${newStatus}`, type: 'info' }
        ],
        currentScan: currentScan ? {
          ...currentScan,
          status: newStatus,
          summary: {
            ...currentScan.summary,
            ...summaryUpdate
          }
        } : currentScan
      });
      // Fetch final complete state
      // Add a small delay to allow backend to finish GCS persistence
      const finalScanId = event.scan_id;
      setTimeout(() => {
        get().loadFindings(finalScanId);
        get().pollScan(finalScanId);
      }, 1000);
      get().disconnectWebSocket();
      break;
    }
      
    case 'connected': {
      set({
        scanLogs: [
          ...scanLogs,
          { timestamp, message: `Connected to scan stream`, type: 'info' }
        ]
      });
      break;
    }

    case 'debug': {
      set({
        scanLogs: [
          ...scanLogs,
          { timestamp, message: `[DEBUG] ${event.data.message}`, type: 'info' }
        ]
      });
      break;
    }
  }
}
