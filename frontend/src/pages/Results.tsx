import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { useScanStore } from '@/stores/scanStore';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie,
} from 'recharts';
import {
  Loader2,
  CheckCircle2,
  ArrowLeft,
  Download,
  Filter,
  X,
  EyeOff,
  Eye,
} from 'lucide-react';
import { formatDuration, formatDate } from '@/lib/utils';
import { SEVERITY_COLORS, SEVERITY_ORDER, CATEGORY_COLORS } from '@/lib/types';
import type { Severity, Category } from '@/lib/types';
import { FindingRow } from '@/components/findings/FindingRow';
import { CheckExecutionRow } from '@/components/dashboard/CheckExecutionRow';
import { StatCard } from '@/components/dashboard/StatCard';
import { HealthScoreCard } from '@/components/dashboard/HealthScoreCard';
import { CostSavingTab } from '@/components/cost/CostSavingTab';
import { useGeminiEnabled, useLogsCommand } from '@/lib/useGeminiEnabled';

export function Results() {
  const { scanId } = useParams<{ scanId: string }>();
  const {
    currentScan, findings, scanLogs, isFetchingFindings,
    toggleSuppressFinding,
  } = useScanStore();
  const geminiEnabled = useGeminiEnabled();
  const logsCommand = useLogsCommand();

  // URL-backed filter state — survives refresh and is shareable. Each setter
  // also pushes the change into the URL via patchParams() below.
  const [searchParams, setSearchParams] = useSearchParams();
  const severityFilter = (searchParams.get('sev') || '') as Severity | '';
  const categoryFilter = (searchParams.get('cat') || '') as Category | '';
  const serviceFilter = searchParams.get('svc') || '';
  const searchQuery = searchParams.get('q') || '';
  const showSuppressed = searchParams.get('suppressed') === '1';
  const checkStatusFilter = (searchParams.get('status') || 'all') as
    'all' | 'passed' | 'failed' | 'errored' | 'skipped';
  const activeTab = (searchParams.get('tab') || 'logs') as 'findings' | 'checks' | 'logs' | 'cost';

  function patchParams(updates: Record<string, string | null>) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [key, value] of Object.entries(updates)) {
        if (!value) next.delete(key);
        else next.set(key, value);
      }
      return next;
    }, { replace: true });
  }
  const setSeverityFilter = (v: Severity | '') => patchParams({ sev: v || null });
  const setCategoryFilter = (v: Category | '') => patchParams({ cat: v || null });
  const setServiceFilter = (v: string) => patchParams({ svc: v || null });
  const setSearchQuery = (v: string) => patchParams({ q: v || null });
  const setShowSuppressed = (next: boolean | ((v: boolean) => boolean)) => {
    const resolved = typeof next === 'function' ? next(showSuppressed) : next;
    patchParams({ suppressed: resolved ? '1' : null });
  };
  const setCheckStatusFilter = (v: 'all' | 'passed' | 'failed' | 'errored' | 'skipped') =>
    patchParams({ status: v === 'all' ? null : v });
  const setActiveTab = (v: 'findings' | 'checks' | 'logs' | 'cost') =>
    patchParams({ tab: v === 'logs' ? null : v });

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Initial load and polling fallback.
  //
  // Actions are pulled from getState() rather than the destructured hook
  // values so the dependency list can honestly be [scanId]. Listing them —
  // along with currentScan?.status and activeTab, as this effect used to —
  // tore down the WebSocket and restarted the interval on every status
  // transition and every tab click.
  useEffect(() => {
    if (!scanId) return;

    const store = useScanStore.getState();
    store.pollScan(scanId);
    store.loadFindings(scanId);
    store.connectWebSocket(scanId);

    // Poll the scan summary every 5s so stat cards tick up even when the
    // WebSocket is unhealthy (Cloud Run sometimes buffers WS for ~30s).
    // Deliberately do NOT call loadFindings on every tick during a running
    // scan — it replaces the entire findings array, which collapses every
    // expanded FindingRow and makes the page un-scrollable. Findings flow
    // via WS event_interceptor as they're discovered; the polling fallback
    // (startPollingFallback in the store) handles the no-WS case separately.
    const interval = setInterval(() => {
      const live = useScanStore.getState();
      const latestScan = live.currentScan;
      if (latestScan?.status === 'running' || latestScan?.status === 'pending') {
        live.pollScan(scanId);
      } else if (latestScan?.status === 'completed' || latestScan?.status === 'failed') {
        clearInterval(interval);
        // One last full refresh after completion to be sure the table
        // matches what the backend persisted.
        live.loadFindings(scanId);
      }
    }, 5000);

    return () => {
      clearInterval(interval);
      useScanStore.getState().disconnectWebSocket();
    };
  }, [scanId]);

  // Auto-scroll logs
  useEffect(() => {
    if (activeTab === 'logs' && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'auto', block: 'end' });
    }
  }, [scanLogs.length, activeTab]);

  // Auto-switch to findings when scan completes
  useEffect(() => {
    if (currentScan?.status === 'completed' && activeTab !== 'findings') {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActiveTab('findings');
    }
  }, [currentScan?.status, activeTab]);

  // "No progress in 60s" diagnostic — fires when a scan is RUNNING but
  // ALL of these progress signals have stayed flat for over a minute:
  //   - scanLogs.length (WebSocket activity)
  //   - findings.length (REST polling delivers new findings)
  //   - any check counter (summary.checks_passed/failed/errored/skipped)
  //
  // Previously this only watched scanLogs and fired false-positively when
  // WS died but polling kept loading findings. Multi-signal makes the
  // banner only appear when the scan genuinely isn't producing output
  // on any channel.
  const [stuckBannerVisible, setStuckBannerVisible] = useState(false);
  const lastProgressSnapshot = useRef({ logs: 0, findings: 0, checks: 0 });
  useEffect(() => {
    const status = currentScan?.status;
    if (status !== 'running' && status !== 'pending') {
      setStuckBannerVisible(false);
      return;
    }
    const snapshot = () => {
      const s = useScanStore.getState();
      const sum = s.currentScan?.summary;
      const checks = (sum?.checks_passed ?? 0)
        + (sum?.checks_failed ?? 0)
        + (sum?.checks_errored ?? 0)
        + (sum?.checks_skipped ?? 0);
      return { logs: s.scanLogs.length, findings: s.findings.length, checks };
    };
    lastProgressSnapshot.current = snapshot();
    const timer = setInterval(() => {
      const now = snapshot();
      const prev = lastProgressSnapshot.current;
      const moved = now.logs !== prev.logs || now.findings !== prev.findings || now.checks !== prev.checks;
      if (moved) {
        setStuckBannerVisible(false);
        lastProgressSnapshot.current = now;
      } else {
        setStuckBannerVisible(true);
      }
    }, 60_000);
    return () => clearInterval(timer);
  }, [currentScan?.status]);

  // Filtered checks
  const filteredChecks = useMemo(() => {
    if (!currentScan) return [];
    if (checkStatusFilter === 'all') return currentScan.check_executions;
    return currentScan.check_executions.filter(ce => ce.status === checkStatusFilter);
  }, [currentScan, checkStatusFilter]);

  // Filtered findings
  const suppressedCount = useMemo(
    () => findings.filter((f) => f.suppressed).length,
    [findings],
  );

  const filteredFindings = useMemo(() => {
    let result = findings;
    if (!showSuppressed) result = result.filter((f) => !f.suppressed);
    if (severityFilter) result = result.filter(f => f.severity === severityFilter);
    if (categoryFilter) result = result.filter(f => f.category === categoryFilter);
    if (serviceFilter) result = result.filter(f => f.service === serviceFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.resource_name.toLowerCase().includes(q) ||
        f.check_id.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    }
    return result;
  }, [findings, severityFilter, categoryFilter, serviceFilter, searchQuery, showSuppressed]);

  // Unique services for filter
  const services = useMemo(() => [...new Set(findings.map(f => f.service))].sort(), [findings]);

  const hasFilters = severityFilter || categoryFilter || serviceFilter || searchQuery;

  if (!currentScan) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-[--color-accent-green]" />
      </div>
    );
  }

  const { summary, status } = currentScan;
  const isRunning = status === 'running' || status === 'pending';
  const hasFindings = (summary?.total_findings || 0) > 0 || findings.length > 0;

  // Chart data
  const severityData = SEVERITY_ORDER.map(s => ({
    name: s.charAt(0).toUpperCase() + s.slice(1),
    value: summary?.by_severity?.[s as Severity] || 0,
    fill: SEVERITY_COLORS[s as Severity],
  })).filter(d => d.value > 0);

  const categoryData = Object.entries(summary?.by_category || {})
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({
      name: k.charAt(0).toUpperCase() + k.slice(1),
      value: v,
      fill: CATEGORY_COLORS[k as Category] || '#8b949e',
    }));

  const serviceData = Object.entries(summary?.by_service || {})
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ name: k, value: v }));

  return (
    <div className="mx-auto max-w-7xl px-4 py-8">
      {/* Back link */}
      <Link to="/scan" className="inline-flex items-center gap-1 text-sm text-[--color-text-secondary] hover:text-[--color-text-primary] mb-6">
        <ArrowLeft className="h-4 w-4" /> New Scan
      </Link>

      {/* Status bar */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="font-mono text-2xl text-[--color-text-primary]">
            Scan Results
            {isRunning && (
              <Loader2 className="inline ml-2 h-5 w-5 animate-spin text-[--color-accent-green]" />
            )}
          </h1>
          <p className="text-sm text-[--color-text-secondary] mt-1">
            {currentScan.scope} / {currentScan.target_id} &bull; {formatDate(currentScan.started_at)}
            {(summary?.scan_duration_seconds || 0) > 0 && ` \u2022 ${formatDuration(summary?.scan_duration_seconds || 0)}`}
          </p>
        </div>
        {scanId && hasFindings && (
          <div className="flex gap-2">
            <a href={`/api/v1/scans/${scanId}/export/csv`}
              className="inline-flex items-center gap-1 rounded border border-[--color-border] bg-[--color-surface] px-3 py-1.5 text-xs font-mono text-[--color-text-secondary] hover:text-[--color-text-primary] hover:border-[--color-text-muted]">
              <Download className="h-3 w-3" /> CSV
            </a>
            <a href={`/api/v1/scans/${scanId}/export/html`}
              className="inline-flex items-center gap-1 rounded border border-[--color-border] bg-[--color-surface] px-3 py-1.5 text-xs font-mono text-[--color-text-secondary] hover:text-[--color-text-primary] hover:border-[--color-text-muted]">
              <Download className="h-3 w-3" /> HTML
            </a>
            <a href={`/api/v1/scans/${scanId}/export/pdf`}
              className="inline-flex items-center gap-1 rounded border border-[--color-border] bg-[--color-surface] px-3 py-1.5 text-xs font-mono text-[--color-text-secondary] hover:text-[--color-text-primary] hover:border-[--color-text-muted]">
              <Download className="h-3 w-3" /> PDF
            </a>
            <Link to={`/export/${scanId}`}
              className="inline-flex items-center gap-1 rounded border border-green-500/50 bg-green-500/10 px-3 py-1.5 text-xs font-mono text-green-400 hover:bg-green-500/20 hover:border-green-500">
              <Download className="h-3 w-3" /> Export &rarr;
            </Link>
          </div>
        )}
      </div>

      {/* "No events in 60s" diagnostic banner. Triggered when the scan is in
          RUNNING or PENDING and the live log stream has been silent for over
          a minute. Most common cause: BackgroundTask died with a Cloud Run
          instance restart, or the SA has no perms and the scan is stuck
          before producing any events. */}
      {stuckBannerVisible && (
        <div className="mb-6 rounded-lg border border-[--color-accent-orange] bg-[--color-accent-orange]/10 p-4">
          <div className="font-mono text-xs uppercase tracking-wider text-[--color-accent-orange] mb-2">
            No progress in the last 60 seconds
          </div>
          <div className="text-sm text-[--color-text-primary] mb-2">
            The scan task may have died (Cloud Run instance restart) or be stuck on the first
            gcloud call (service account has no permission on the target project).
          </div>
          <div className="text-xs text-[--color-text-secondary]">
            Check the backend logs to confirm:
          </div>
          <pre className="mt-1 rounded bg-[--color-background] border border-[--color-border-light] px-3 py-2 text-xs font-mono text-[--color-accent-blue] overflow-x-auto">
{logsCommand}
          </pre>
        </div>
      )}

      {/* Health score — surfaced first so the top-line posture grade is immediate */}
      {!isRunning && summary && summary.health_score !== undefined && summary.health_grade && (
        <div className="mb-6">
          <HealthScoreCard score={summary.health_score} grade={summary.health_grade} />
        </div>
      )}

      {/* Severity grid — responsive: 2 cols on mobile, 5 on md+ */}
      <div className="mb-8">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <button key={sev} onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev as Severity)}
              className={`rounded-lg border p-4 text-center transition-colors cursor-pointer ${
                severityFilter === sev
                  ? 'border-[--color-accent-green] bg-[--color-accent-green]/5'
                  : 'border-[--color-border] bg-[--color-surface] hover:border-[--color-text-muted]'
              }`}>
              <div className="text-3xl font-mono font-bold" style={{ color: SEVERITY_COLORS[sev as Severity] }}>
                {summary?.by_severity?.[sev as Severity] || 0}
              </div>
              <div className="text-xs text-[--color-text-muted] mt-1 capitalize">{sev}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Stats + Charts */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
        <StatCard
          label="Total Findings"
          value={summary?.total_findings || 0}
          onClick={() => setActiveTab('findings')}
          active={activeTab === 'findings'}
        />
        <StatCard
          label="Passed"
          value={summary?.checks_passed || 0}
          color="text-[--color-accent-green]"
          onClick={() => { setCheckStatusFilter(checkStatusFilter === 'passed' ? 'all' : 'passed'); setActiveTab('checks'); }}
          active={checkStatusFilter === 'passed' && activeTab === 'checks'}
        />
        <StatCard
          label="Failed"
          value={summary?.checks_failed || 0}
          color="text-[--color-accent-red]"
          onClick={() => { setCheckStatusFilter(checkStatusFilter === 'failed' ? 'all' : 'failed'); setActiveTab('checks'); }}
          active={checkStatusFilter === 'failed' && activeTab === 'checks'}
        />
        <StatCard
          label="Errors"
          value={summary?.checks_errored || 0}
          color="text-[--color-accent-orange]"
          onClick={() => { setCheckStatusFilter(checkStatusFilter === 'errored' ? 'all' : 'errored'); setActiveTab('checks'); }}
          active={checkStatusFilter === 'errored' && activeTab === 'checks'}
        />
        <StatCard
          label="Skipped"
          value={summary?.checks_skipped || 0}
          color="text-[--color-text-muted]"
          onClick={() => { setCheckStatusFilter(checkStatusFilter === 'skipped' ? 'all' : 'skipped'); setActiveTab('checks'); }}
          active={checkStatusFilter === 'skipped' && activeTab === 'checks'}
        />
      </div>

      {/* Charts row */}
      {!isRunning && (summary?.total_findings || 0) > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
          {/* Severity Pie */}
          <div className="rounded-lg border border-[--color-border] bg-[--color-surface] p-4">
            <h3 className="font-mono text-xs text-[--color-text-muted] mb-3 uppercase tracking-wider">By Severity</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                  outerRadius={65} strokeWidth={0} label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false} fontSize={10} fill="#8884d8">
                  {severityData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Category Pie */}
          <div className="rounded-lg border border-[--color-border] bg-[--color-surface] p-4">
            <h3 className="font-mono text-xs text-[--color-text-muted] mb-3 uppercase tracking-wider">By Category</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={categoryData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                  outerRadius={65} strokeWidth={0} label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false} fontSize={10} fill="#8884d8">
                  {categoryData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Service Bar */}
          <div className="rounded-lg border border-[--color-border] bg-[--color-surface] p-4">
            <h3 className="font-mono text-xs text-[--color-text-muted] mb-3 uppercase tracking-wider">By Service</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={serviceData} layout="vertical" margin={{ left: 0, right: 10 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" width={70} tick={{ fontSize: 10, fill: '#8b949e' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#e6edf3' }}
                />
                <Bar dataKey="value" fill="#58a6ff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex items-center gap-4 border-b border-[--color-border] mb-4">
        <button onClick={() => setActiveTab('findings')}
          className={`px-3 py-2 text-sm font-mono border-b-2 transition-colors ${
            activeTab === 'findings'
              ? 'border-[--color-accent-green] text-[--color-text-primary]'
              : 'border-transparent text-[--color-text-muted] hover:text-[--color-text-secondary]'
          }`}>
          Findings ({filteredFindings.length}{hasFilters ? ` / ${findings.length}` : ''})
        </button>
        <button onClick={() => setActiveTab('checks')}
          className={`px-3 py-2 text-sm font-mono border-b-2 transition-colors ${
            activeTab === 'checks'
              ? 'border-[--color-accent-green] text-[--color-text-primary]'
              : 'border-transparent text-[--color-text-muted] hover:text-[--color-text-secondary]'
          }`}>
          Check Executions ({currentScan.check_executions.length})
        </button>
        <button onClick={() => setActiveTab('logs')}
          className={`px-3 py-2 text-sm font-mono border-b-2 transition-colors ${
            activeTab === 'logs'
              ? 'border-[--color-accent-green] text-[--color-text-primary]'
              : 'border-transparent text-[--color-text-muted] hover:text-[--color-text-secondary]'
          }`}>
          Live Logs
        </button>
        {currentScan.status === 'completed' && geminiEnabled && (
          <button onClick={() => setActiveTab('cost')}
            className={`px-3 py-2 text-sm font-mono border-b-2 transition-colors ${
              activeTab === 'cost'
                ? 'border-[--color-accent-green] text-[--color-text-primary]'
                : 'border-transparent text-[--color-text-muted] hover:text-[--color-text-secondary]'
            }`}>
            Cost Saving
          </button>
        )}
      </div>

      {activeTab === 'findings' && (
        <>
          {/* Filter bar */}
          <div className="flex items-center gap-3 mb-4">
            <Filter className="h-4 w-4 text-[--color-text-muted]" />
            <input
              type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search findings..."
              className="flex-1 max-w-xs rounded border border-[--color-border] bg-[--color-background] px-3 py-1.5 text-xs font-mono text-[--color-text-primary] placeholder:text-[--color-text-muted] focus:border-[--color-accent-green] focus:outline-none"
            />
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as Severity | '')}
              className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none">
              <option value="" className="bg-[#0d1117] text-white">All Severities</option>
              {SEVERITY_ORDER.map(s => <option key={s} value={s} className="bg-[#0d1117] text-white">{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
            <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value as Category | '')}
              className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none">
              <option value="" className="bg-[#0d1117] text-white">All Categories</option>
              {['security', 'reliability', 'performance', 'cost', 'operations'].map(c =>
                <option key={c} value={c} className="bg-[#0d1117] text-white">{c.charAt(0).toUpperCase() + c.slice(1)}</option>
              )}
            </select>
            <select value={serviceFilter} onChange={e => setServiceFilter(e.target.value)}
              className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none">
              <option value="" className="bg-[#0d1117] text-white">All Services</option>
              {services.map(s => <option key={s} value={s} className="bg-[#0d1117] text-white">{s}</option>)}
            </select>
            {hasFilters && (
              <button onClick={() => { setSeverityFilter(''); setCategoryFilter(''); setServiceFilter(''); setSearchQuery(''); }}
                className="text-xs text-[--color-accent-red] hover:underline flex items-center gap-1">
                <X className="h-3 w-3" /> Clear
              </button>
            )}
            {suppressedCount > 0 && (
              <button
                onClick={() => setShowSuppressed((v) => !v)}
                title={showSuppressed ? 'Hide suppressed findings' : 'Show suppressed findings'}
                className="ml-auto inline-flex items-center gap-1 rounded border border-[--color-border] bg-[--color-surface] px-2 py-1 text-xs font-mono text-[--color-text-secondary] hover:text-[--color-text-primary] hover:border-[--color-text-muted]"
              >
                {showSuppressed ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
                {showSuppressed ? 'Showing' : 'Hidden'} {suppressedCount} suppressed
              </button>
            )}
          </div>

          {/* Findings table */}
          <div className="rounded-lg border border-[--color-border] bg-[--color-surface]">
            {isFetchingFindings ? (
              <div className="py-24 text-center">
                <Loader2 className="mx-auto h-8 w-8 animate-spin text-[--color-accent-green] mb-3" />
                <div className="text-[--color-text-muted] font-mono">Loading findings...</div>
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="py-16 text-center">
                {isRunning ? (
                  <div className="text-[--color-text-muted]">
                    <Loader2 className="mx-auto h-8 w-8 animate-spin text-[--color-accent-green] mb-3" />
                    Scanning...
                  </div>
                ) : hasFilters ? (
                  <div className="text-[--color-text-muted] font-mono text-sm">
                    No findings match filters
                  </div>
                ) : (
                  <div className="text-[--color-accent-green] font-mono">
                    <CheckCircle2 className="mx-auto h-8 w-8 mb-3" />
                    No findings — your cloud looks clean!
                  </div>
                )}
              </div>
            ) : (
              <div className="divide-y divide-[--color-border-light]">
                {filteredFindings.map((f) => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    onToggleSuppress={() =>
                      scanId && toggleSuppressFinding(scanId, f.id)
                    }
                  />
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'checks' && (
        <div className="rounded-lg border border-[--color-border] bg-[--color-surface]">
          {checkStatusFilter !== 'all' && (
             <div className="px-4 py-2 text-xs text-[--color-text-muted] border-b border-[--color-border-light] flex justify-between items-center">
               <span>Filtering by status: <span className="font-bold text-white capitalize">{checkStatusFilter}</span></span>
               <button onClick={() => setCheckStatusFilter('all')} className="hover:text-white transition-colors">Clear Filter</button>
             </div>
          )}
          <div className="divide-y divide-[--color-border-light]">
            {filteredChecks.length === 0 ? (
              <div className="py-8 text-center text-[--color-text-muted]">No checks found with status: {checkStatusFilter}</div>
            ) : (
              filteredChecks.map((ce) => (
                <CheckExecutionRow key={ce.check_id} execution={ce} />
              ))
            )}
          </div>
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="rounded-lg border border-[--color-border] bg-[#0d1117] p-4 font-mono text-xs overflow-y-auto max-h-[600px]">
          {scanLogs.length === 0 ? (
            <div className="text-[--color-text-muted] italic">Waiting for logs...</div>
          ) : (
            <div className="space-y-1">
              {scanLogs.map((log, i) => (
                <div key={i} className="flex gap-3">
                  <span className="text-[--color-text-muted] shrink-0 w-32">{new Date(log.timestamp).toLocaleTimeString()}</span>
                  <span className={`${
                    log.type === 'error' ? 'text-[--color-accent-red]' :
                    log.type === 'warning' ? 'text-[--color-accent-orange]' :
                    log.type === 'success' ? 'text-[--color-accent-green]' :
                    'text-[--color-text-primary]'
                  }`}>
                    {log.message}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      )}

      {activeTab === 'cost' && currentScan.status === 'completed' && geminiEnabled && (
        <CostSavingTab scan={currentScan} findings={findings} />
      )}
    </div>
  );
}

