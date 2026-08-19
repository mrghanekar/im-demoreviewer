import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Search, Loader2 } from 'lucide-react';
import { fetchChecksCatalog } from '@/lib/api';
import { FRAMEWORK_LABELS, SEVERITY_COLORS } from '@/lib/types';
import type { CheckCatalogEntry, Severity } from '@/lib/types';

/** "ISO 27001 A.8.20, A.8.22" — one badge per framework a check maps to. */
function complianceBadges(refs: Record<string, string[]> | undefined): string[] {
  if (!refs) return [];
  return Object.entries(refs).map(
    ([framework, controls]) =>
      `${FRAMEWORK_LABELS[framework] ?? framework} ${controls.join(', ')}`,
  );
}

/**
 * Browse the live check catalog without starting a scan.
 * Reads /api/v1/setup/checks/catalog — same source of truth the scan engine
 * uses, so this never drifts from what the scanner actually runs.
 */
export function Catalog() {
  const [entries, setEntries] = useState<CheckCatalogEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [serviceFilter, setServiceFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [frameworkFilter, setFrameworkFilter] = useState('');

  useEffect(() => {
    fetchChecksCatalog()
      .then(setEntries)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const services = useMemo(
    () => (entries ? [...new Set(entries.map((e) => e.service))].sort() : []),
    [entries],
  );

  const frameworks = useMemo(
    () =>
      entries
        ? [...new Set(entries.flatMap((e) => Object.keys(e.compliance_refs ?? {})))].sort()
        : [],
    [entries],
  );

  const filtered = useMemo(() => {
    if (!entries) return [];
    let result = entries;
    if (serviceFilter) result = result.filter((e) => e.service === serviceFilter);
    if (severityFilter) result = result.filter((e) => e.severity === severityFilter);
    if (frameworkFilter) {
      result = result.filter((e) => frameworkFilter in (e.compliance_refs ?? {}));
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.id.toLowerCase().includes(q) ||
          e.title.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          // So an auditor can search "A.8.20" and see every check behind it.
          complianceBadges(e.compliance_refs).some((b) => b.toLowerCase().includes(q)),
      );
    }
    return result;
  }, [entries, serviceFilter, severityFilter, frameworkFilter, search]);

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <Link to="/" className="inline-flex items-center gap-1 text-sm text-[--color-text-secondary] hover:text-[--color-text-primary] mb-6">
        <ArrowLeft className="h-4 w-4" /> Home
      </Link>

      <h1 className="font-mono text-2xl text-[--color-text-primary] mb-2">Check Catalog</h1>
      <p className="text-sm text-[--color-text-secondary] mb-6">
        Live list of every check the scanner can run. Filter to confirm the tool
        covers what you care about before starting a scan. Framework badges show
        which control a check is evidence for — a passing check attests to the
        technical configuration, not to certification.
      </p>

      {error && (
        <div className="rounded border border-[--color-accent-red]/40 bg-[--color-accent-red]/10 p-4 text-sm text-[--color-accent-red] mb-4">
          Failed to load catalog: {error}
        </div>
      )}

      {!entries && !error && (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-[--color-accent-green]" />
        </div>
      )}

      {entries && (
        <>
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[--color-text-muted]" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by ID, title, description..."
                className="w-full rounded border border-[--color-border] bg-[--color-background] pl-8 pr-3 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none focus:border-[--color-accent-green]"
              />
            </div>
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none"
            >
              <option value="" className="bg-[#0d1117]">All services</option>
              {services.map((s) => (
                <option key={s} value={s} className="bg-[#0d1117]">{s}</option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
              className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none"
            >
              <option value="" className="bg-[#0d1117]">All severities</option>
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => (
                <option key={s} value={s} className="bg-[#0d1117]">{s}</option>
              ))}
            </select>
            {frameworks.length > 0 && (
              <select
                value={frameworkFilter}
                onChange={(e) => setFrameworkFilter(e.target.value)}
                className="rounded border border-[--color-border] bg-[--color-background] px-2 py-1.5 text-xs font-mono text-[--color-text-primary] focus:outline-none"
              >
                <option value="" className="bg-[#0d1117]">All frameworks</option>
                {frameworks.map((f) => (
                  <option key={f} value={f} className="bg-[#0d1117]">
                    {FRAMEWORK_LABELS[f] ?? f}
                  </option>
                ))}
              </select>
            )}
            <span className="ml-auto text-xs font-mono text-[--color-text-muted]">
              {filtered.length} / {entries.length}
            </span>
          </div>

          <div className="rounded-lg border border-[--color-border] bg-[--color-surface] divide-y divide-[--color-border-light]">
            {filtered.length === 0 ? (
              <div className="py-12 text-center text-[--color-text-muted] font-mono text-sm">
                No checks match the filter.
              </div>
            ) : (
              filtered.map((c) => (
                <div key={c.id} className="px-4 py-3 flex items-start gap-3">
                  <span
                    className="inline-block w-2 h-2 rounded-full mt-1.5 shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[c.severity as Severity] }}
                    title={c.severity}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-[--color-text-muted]">{c.id}</span>
                      <span className="text-sm text-[--color-text-primary] font-medium">{c.title}</span>
                    </div>
                    {c.description && (
                      <p className="text-xs text-[--color-text-secondary] mt-1">{c.description}</p>
                    )}
                    {complianceBadges(c.compliance_refs).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {complianceBadges(c.compliance_refs).map((badge) => (
                          <span
                            key={badge}
                            className="rounded border border-[--color-border] px-1.5 py-0.5 text-[10px] font-mono text-[--color-text-muted]"
                          >
                            {badge}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="rounded bg-[--color-background] px-2 py-0.5 text-[10px] font-mono text-[--color-text-muted] capitalize shrink-0">
                    {c.service}
                  </span>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
