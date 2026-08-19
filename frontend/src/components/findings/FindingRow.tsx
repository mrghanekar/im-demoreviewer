import { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  Sparkles,
  Eye,
  EyeOff,
} from 'lucide-react';
import { copyToClipboard } from '@/lib/utils';
import { explainFinding, ApiError } from '@/lib/api';
import { useGeminiEnabled } from '@/lib/useGeminiEnabled';
import { SeverityBadge } from './SeverityBadge';
import type { Finding } from '@/lib/types';

export function FindingRow({
  finding,
  onToggleSuppress,
}: {
  finding: Finding;
  onToggleSuppress?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const geminiEnabled = useGeminiEnabled();

  const handleCopy = async () => {
    if (finding.fix_command) {
      await copyToClipboard(finding.fix_command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleExplain = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (explanation) return;

    setExplaining(true);
    try {
      const res = await explainFinding(finding);
      setExplanation(res.explanation);
    } catch (err) {
      console.error(err);
      let msg = 'Failed to generate explanation.';
      if (err instanceof ApiError) {
        msg = `Error: ${err.detail}`;
      } else if (err instanceof Error) {
        msg = `Error: ${err.message}`;
      }
      setExplanation(msg);
    } finally {
      setExplaining(false);
    }
  };

  return (
    <div className={`transition-colors ${finding.suppressed ? 'opacity-50' : ''}`}>
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        className="px-4 py-3 hover:bg-[--color-surface-hover] cursor-pointer flex items-start gap-3 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[--color-accent-green]"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => {
          if (e.key !== 'Enter' && e.key !== ' ') return;
          // Space would otherwise scroll the page
          if (e.key === ' ') e.preventDefault();
          setExpanded(!expanded);
        }}
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-[--color-text-muted] mt-0.5 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-[--color-text-muted] mt-0.5 shrink-0" />
        )}
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-[--color-text-muted]">{finding.check_id}</span>
            <span className="text-sm text-[--color-text-primary] font-medium">{finding.title}</span>
            {finding.suppressed && (
              <span className="rounded bg-[--color-background] px-1.5 py-0.5 text-[10px] font-mono text-[--color-text-muted] uppercase tracking-wider">
                Suppressed
              </span>
            )}
          </div>
          <div className="text-xs text-[--color-text-secondary] mt-0.5 truncate">
            {finding.resource_name}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="rounded bg-[--color-background] px-2 py-0.5 text-xs font-mono text-[--color-text-muted] capitalize">
            {finding.category}
          </span>
          {finding.resource_link && (
            <a
              href={finding.resource_link}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[--color-accent-blue] hover:opacity-80"
              onClick={(e) => e.stopPropagation()}
              aria-label="Open in Cloud Console"
            >
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
          {onToggleSuppress && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onToggleSuppress();
              }}
              title={
                finding.suppressed
                  ? 'Unsuppress this finding'
                  : 'Suppress this finding (hide from default views)'
              }
              aria-label={finding.suppressed ? 'Unsuppress finding' : 'Suppress finding'}
              className="text-[--color-text-muted] hover:text-[--color-text-primary]"
            >
              {finding.suppressed ? (
                <Eye className="h-3.5 w-3.5" />
              ) : (
                <EyeOff className="h-3.5 w-3.5" />
              )}
            </button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 pl-14 space-y-3 bg-[--color-background]/50 border-t border-[--color-border-light]">
          <div className="flex justify-between items-start gap-4">
            <div className="flex-1">
              {finding.description && (
                <div>
                  <div className="text-xs font-mono text-[--color-text-muted] mb-1 uppercase tracking-wider">
                    Description
                  </div>
                  <p className="text-sm text-[--color-text-secondary]">{finding.description}</p>
                </div>
              )}
            </div>
            {geminiEnabled && (
              <button
                onClick={handleExplain}
                disabled={explaining}
                className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-purple-500/30 bg-purple-500/10 text-purple-400 text-xs font-mono hover:bg-purple-500/20 disabled:opacity-50 transition-colors"
              >
                {explaining ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />}
                {explaining ? 'Analyzing...' : 'Gemini Intelligence'}
              </button>
            )}
          </div>

          {explanation && (
            <div className="rounded-md border border-purple-500/30 bg-purple-500/5 p-4 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center gap-2 text-purple-400 mb-2 font-mono text-xs uppercase tracking-wider font-bold">
                <Sparkles className="h-3 w-3" /> Gemini Analysis
              </div>
              <div className="text-sm text-[--color-text-primary] whitespace-pre-wrap leading-relaxed font-sans">
                {explanation}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-xs font-mono text-[--color-text-muted] mb-1 uppercase tracking-wider">
                Current State
              </div>
              <p className="text-sm text-[--color-accent-red]">{finding.current_state}</p>
            </div>
            <div>
              <div className="text-xs font-mono text-[--color-text-muted] mb-1 uppercase tracking-wider">
                Recommended
              </div>
              <p className="text-sm text-[--color-accent-green]">{finding.recommended_state}</p>
            </div>
          </div>
          {finding.fix_command && (
            <div>
              <div className="text-xs font-mono text-[--color-text-muted] mb-1 uppercase tracking-wider flex items-center gap-2">
                Fix Command
                <button
                  onClick={handleCopy}
                  aria-label="Copy fix command"
                  className="text-[--color-accent-blue] hover:opacity-80 transition-opacity"
                >
                  {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                </button>
              </div>
              <pre className="rounded bg-[--color-background] border border-[--color-border-light] px-3 py-2 text-xs font-mono text-[--color-accent-green] overflow-x-auto">
                {finding.fix_command}
              </pre>
            </div>
          )}
          {finding.references.length > 0 && (
            <div>
              <div className="text-xs font-mono text-[--color-text-muted] mb-1 uppercase tracking-wider">
                References
              </div>
              <div className="space-y-1">
                {finding.references.map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-xs text-[--color-accent-blue] hover:underline truncate"
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
