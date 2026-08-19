import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  DollarSign,
  Loader2,
  RefreshCw,
  Sparkles,
  ExternalLink,
} from 'lucide-react';

import {
  getCostAnalysis,
  getCostEstimate,
  startCostAnalysis,
  ApiError,
} from '@/lib/api';
import type { Finding, Scan } from '@/lib/types';

type SortMode = 'cost' | 'severity';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const currency = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 2,
});

function formatUsd(n: number): string {
  if (!Number.isFinite(n)) return '—';
  return currency.format(n);
}

function IdleState({
  scan,
  findingsCount,
  showEstimate,
  onShowEstimate,
  estimate,
  estimateLoading,
  onStart,
  starting,
  startError,
}: {
  scan: Scan;
  findingsCount: number;
  showEstimate: boolean;
  onShowEstimate: () => void;
  estimate: { findings_to_analyze: number; estimated_usd: number; estimated_tokens_in: number; estimated_tokens_out: number; model: string } | undefined;
  estimateLoading: boolean;
  onStart: () => void;
  starting: boolean;
  startError: string | null;
}) {
  const projectLabel = scan.scope === 'project' ? scan.target_id : '(deploy project)';
  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h2 className="text-lg font-mono text-[--color-text-primary] flex items-center gap-2">
          <DollarSign className="h-5 w-5 text-[--color-accent-green]" />
          Cost Saving Analysis
        </h2>
        <p className="text-sm text-[--color-text-secondary] mt-2">
          Send every finding with a cloud resource to Gemini, grounded with
          Google Search, so it can pull current pricing from cloud.google.com
          and estimate how much each idle / oversized / orphaned resource is
          costing per month.
        </p>
      </div>

      <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-4 space-y-3">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 shrink-0" />
          <div className="text-sm text-[--color-text-primary] space-y-2">
            <p>
              This will call the <strong>Gemini API in your GCP project</strong>{' '}
              (<code className="font-mono text-xs">{projectLabel}</code>) and the
              tokens will appear on your Vertex AI bill.
            </p>
            <p className="text-[--color-text-secondary]">
              The model uses <strong>Google Search grounding</strong> to pull
              current cloud.google.com pricing pages, so results reflect today's
              list prices (CUD / contract discounts not modelled).
            </p>
            <p className="text-[--color-text-secondary]">
              Rough cost: ~$0.05–$0.20 per scan with{' '}
              <code className="font-mono text-xs">gemini-3-flash</code>.
            </p>
          </div>
        </div>

        {showEstimate && (
          <div className="ml-8 rounded border border-[--color-border] bg-[--color-background] p-3 text-xs font-mono">
            {estimateLoading && (
              <span className="text-[--color-text-muted]">Computing estimate…</span>
            )}
            {estimate && (
              <div className="space-y-1 text-[--color-text-primary]">
                <div>
                  Findings to analyze:{' '}
                  <span className="text-[--color-accent-green]">{estimate.findings_to_analyze}</span>
                </div>
                <div>Model: {estimate.model}</div>
                <div>
                  Tokens (in / out): {estimate.estimated_tokens_in.toLocaleString()} /{' '}
                  {estimate.estimated_tokens_out.toLocaleString()}
                </div>
                <div className="text-[--color-accent-green] pt-1">
                  Estimated bill for this scan: {formatUsd(estimate.estimated_usd)}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {startError && (
        <div className="rounded-md border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-300">
          {startError}
        </div>
      )}

      <div className="flex items-center gap-4">
        <button
          onClick={onStart}
          disabled={starting || findingsCount === 0}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[--color-accent-green]/10 border border-[--color-accent-green] text-[--color-accent-green] font-mono text-sm rounded-md hover:bg-[--color-accent-green]/20 disabled:opacity-50 transition-colors"
        >
          {starting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Sparkles className="h-4 w-4" />
          )}
          {starting ? 'Starting…' : 'Compute Costs'}
        </button>
        {!showEstimate && (
          <button
            onClick={onShowEstimate}
            className="text-xs text-[--color-accent-blue] hover:underline"
          >
            Show estimated token spend first
          </button>
        )}
        <span className="text-xs text-[--color-text-muted]">
          {findingsCount} finding{findingsCount === 1 ? '' : 's'} with resources will be analyzed.
        </span>
      </div>
    </div>
  );
}

function RunningState({ analysis }: { analysis: NonNullable<Scan['cost_analysis']> }) {
  return (
    <div className="max-w-3xl flex items-start gap-3 p-6 rounded-md border border-[--color-border] bg-[--color-surface]">
      <Loader2 className="h-5 w-5 animate-spin text-[--color-accent-green] mt-0.5" />
      <div className="space-y-1">
        <div className="text-sm text-[--color-text-primary]">
          Gemini is pricing {analysis.findings_count} finding
          {analysis.findings_count === 1 ? '' : 's'}…
        </div>
        <div className="text-xs text-[--color-text-muted]">
          Usually takes 30–90 seconds. The page updates automatically.
        </div>
      </div>
    </div>
  );
}

function FailedState({
  analysis,
  onRetry,
  retrying,
}: {
  analysis: NonNullable<Scan['cost_analysis']>;
  onRetry: () => void;
  retrying: boolean;
}) {
  return (
    <div className="max-w-3xl space-y-4">
      <div className="rounded-md border border-red-500/40 bg-red-500/5 p-4">
        <div className="text-sm text-red-300 font-mono mb-2">Cost analysis failed</div>
        <pre className="text-xs text-[--color-text-secondary] whitespace-pre-wrap">
          {analysis.error_message || 'Unknown error.'}
        </pre>
      </div>
      <button
        onClick={onRetry}
        disabled={retrying}
        className="inline-flex items-center gap-2 px-4 py-2 bg-[--color-accent-green]/10 border border-[--color-accent-green] text-[--color-accent-green] font-mono text-sm rounded-md hover:bg-[--color-accent-green]/20 disabled:opacity-50"
      >
        {retrying ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
        Retry
      </button>
    </div>
  );
}

export function CostSavingTab({
  scan,
  findings,
}: {
  scan: Scan;
  findings: Finding[];
}) {
  const scanId = scan.id;
  const queryClient = useQueryClient();
  const [sortMode, setSortMode] = useState<SortMode>('cost');
  const [showZero, setShowZero] = useState(false);
  const [showEstimate, setShowEstimate] = useState(false);

  // Tab-level fetch of cost analysis. Throws 404 when not yet started; we
  // swallow that and fall back to scan.cost_analysis (which is null before
  // the user clicks the button).
  const analysisQuery = useQuery({
    queryKey: ['cost-analysis', scanId],
    queryFn: async () => {
      try {
        return await getCostAnalysis(scanId);
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) return null;
        throw err;
      }
    },
    refetchInterval: (q) => {
      const status = (q.state.data as { status?: string } | null | undefined)?.status;
      return status === 'running' ? 3000 : false;
    },
  });
  const analysis = analysisQuery.data ?? scan.cost_analysis ?? null;

  // When a running analysis completes, refresh the findings list so the
  // patched $/mo values land in the Findings tab too.
  useEffect(() => {
    if (analysis?.status === 'completed') {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
      queryClient.invalidateQueries({ queryKey: ['findings', scanId] });
    }
  }, [analysis?.status, queryClient, scanId]);

  const estimateQuery = useQuery({
    queryKey: ['cost-estimate', scanId],
    queryFn: () => getCostEstimate(scanId),
    enabled: showEstimate && !analysis,
  });

  const startMut = useMutation({
    mutationFn: (force: boolean) => startCostAnalysis(scanId, force),
    onSuccess: (data) => {
      queryClient.setQueryData(['cost-analysis', scanId], data);
    },
  });

  if (!analysis || analysis.status === 'pending') {
    return (
      <IdleState
        scan={scan}
        findingsCount={findings.filter((f) => f.resource_name).length}
        showEstimate={showEstimate}
        onShowEstimate={() => setShowEstimate(true)}
        estimate={estimateQuery.data}
        estimateLoading={estimateQuery.isLoading}
        onStart={() => startMut.mutate(false)}
        starting={startMut.isPending}
        startError={
          startMut.error instanceof ApiError
            ? startMut.error.detail
            : startMut.error instanceof Error
              ? startMut.error.message
              : null
        }
      />
    );
  }

  if (analysis.status === 'running') {
    return <RunningState analysis={analysis} />;
  }

  if (analysis.status === 'failed') {
    return (
      <FailedState
        analysis={analysis}
        onRetry={() => startMut.mutate(true)}
        retrying={startMut.isPending}
      />
    );
  }

  // Completed
  return (
    <CompletedState
      analysis={analysis}
      findings={findings}
      sortMode={sortMode}
      setSortMode={setSortMode}
      showZero={showZero}
      setShowZero={setShowZero}
      onRerun={() => startMut.mutate(true)}
      rerunning={startMut.isPending}
    />
  );
}

function CompletedState({
  analysis,
  findings,
  sortMode,
  setSortMode,
  showZero,
  setShowZero,
  onRerun,
  rerunning,
}: {
  analysis: NonNullable<Scan['cost_analysis']>;
  findings: Finding[];
  sortMode: SortMode;
  setSortMode: (m: SortMode) => void;
  showZero: boolean;
  setShowZero: (v: boolean) => void;
  onRerun: () => void;
  rerunning: boolean;
}) {
  const priced = useMemo(
    () => findings.filter((f) => (f.estimated_monthly_cost_usd ?? 0) > 0),
    [findings],
  );
  const unpriced = useMemo(
    () =>
      findings.filter(
        (f) => f.resource_name && !(f.estimated_monthly_cost_usd && f.estimated_monthly_cost_usd > 0),
      ),
    [findings],
  );

  const sortedPriced = useMemo(() => {
    const list = [...priced];
    if (sortMode === 'cost') {
      list.sort((a, b) => (b.estimated_monthly_cost_usd || 0) - (a.estimated_monthly_cost_usd || 0));
    } else {
      list.sort(
        (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9),
      );
    }
    return list;
  }, [priced, sortMode]);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end gap-6 justify-between">
        <div>
          <div className="text-xs font-mono text-[--color-text-muted] uppercase tracking-wider">
            Potential monthly waste
          </div>
          <div className="text-4xl font-mono font-bold text-[--color-accent-green] mt-1">
            {formatUsd(analysis.total_monthly_usd)}
            <span className="text-base text-[--color-text-muted] ml-1">/ mo</span>
          </div>
          <div className="text-xs text-[--color-text-secondary] mt-2 max-w-2xl">
            {analysis.notes}
          </div>
          <div className="text-[10px] font-mono text-[--color-text-muted] mt-1">
            Computed by <span className="text-[--color-accent-blue]">{analysis.model}</span> at{' '}
            {analysis.completed_at ? new Date(analysis.completed_at).toLocaleString() : '—'}
            {' · '}
            {analysis.costed_count} of {analysis.findings_count} resources had measurable cost
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={sortMode}
            onChange={(e) => setSortMode(e.target.value as SortMode)}
            className="bg-[--color-background] border border-[--color-border] rounded px-2 py-1 text-xs font-mono text-[--color-text-primary]"
          >
            <option value="cost">Sort: cost (high → low)</option>
            <option value="severity">Sort: severity</option>
          </select>
          <button
            onClick={onRerun}
            disabled={rerunning}
            className="inline-flex items-center gap-1.5 px-3 py-1 border border-[--color-border] hover:border-[--color-accent-green] text-xs font-mono text-[--color-text-muted] hover:text-[--color-accent-green] rounded disabled:opacity-50"
            title="Re-run analysis (counts against your Gemini bill again)"
          >
            {rerunning ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            Re-run
          </button>
        </div>
      </header>

      {sortedPriced.length === 0 ? (
        <div className="rounded-md border border-[--color-border] bg-[--color-surface] p-6 text-sm text-[--color-text-secondary]">
          Gemini didn't identify any resources with a measurable monthly cost.
          That can mean the resources have no recurring charge (e.g. IAM policies),
          or that pricing pages couldn't be located for them. See the unpriced
          list below.
        </div>
      ) : (
        <div className="rounded-md border border-[--color-border] bg-[--color-surface] overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[--color-background] text-xs font-mono text-[--color-text-muted] uppercase tracking-wider">
              <tr>
                <th className="text-left px-3 py-2 w-20">Severity</th>
                <th className="text-left px-3 py-2 w-24">Check</th>
                <th className="text-left px-3 py-2">Resource</th>
                <th className="text-right px-3 py-2 w-24">$ / mo</th>
                <th className="text-left px-3 py-2 w-2/5">Basis</th>
              </tr>
            </thead>
            <tbody>
              {sortedPriced.map((f) => (
                <tr
                  key={f.id}
                  className="border-t border-[--color-border-light] hover:bg-[--color-surface-hover]"
                >
                  <td className="px-3 py-2 capitalize text-xs font-mono text-[--color-text-secondary]">
                    {f.severity}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-[--color-text-muted]">
                    {f.check_id}
                  </td>
                  <td className="px-3 py-2 text-xs text-[--color-text-primary]">
                    <div className="font-medium">{f.title}</div>
                    <div className="text-[--color-text-muted] font-mono mt-0.5 truncate">
                      {f.resource_name}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-right font-mono font-bold text-[--color-accent-green]">
                    {formatUsd(f.estimated_monthly_cost_usd!)}
                  </td>
                  <td className="px-3 py-2 text-xs text-[--color-text-secondary]">
                    {f.cost_basis || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {unpriced.length > 0 && (
        <details
          open={showZero}
          onToggle={(e) => setShowZero((e.target as HTMLDetailsElement).open)}
          className="rounded-md border border-[--color-border] bg-[--color-surface]"
        >
          <summary className="cursor-pointer select-none px-3 py-2 text-xs font-mono text-[--color-text-muted] hover:text-[--color-text-primary]">
            Show {unpriced.length} resource{unpriced.length === 1 ? '' : 's'} with no measurable cost impact
          </summary>
          <ul className="px-3 pb-3 space-y-1 text-xs text-[--color-text-secondary]">
            {unpriced.map((f) => (
              <li key={f.id}>
                <span className="font-mono text-[--color-text-muted]">{f.check_id}</span>{' '}
                {f.title}{' '}
                <span className="font-mono text-[--color-text-muted]">— {f.resource_name}</span>
              </li>
            ))}
          </ul>
        </details>
      )}

      {analysis.grounding_sources.length > 0 && (
        <section className="border-t border-[--color-border] pt-4">
          <div className="text-xs font-mono text-[--color-text-muted] uppercase tracking-wider mb-2">
            Pricing sources Gemini cited
          </div>
          <ul className="space-y-1">
            {analysis.grounding_sources.map((url) => (
              <li key={url}>
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[--color-accent-blue] hover:underline inline-flex items-center gap-1 break-all"
                >
                  {url}
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
