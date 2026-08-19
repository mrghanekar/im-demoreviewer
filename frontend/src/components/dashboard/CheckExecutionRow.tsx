import { CheckCircle2, Loader2 } from 'lucide-react';
import { SERVICE_LABELS } from '@/lib/types';
import type { CheckExecution } from '@/lib/types';

export function CheckExecutionRow({ execution }: { execution: CheckExecution }) {
  const statusIcon = () => {
    switch (execution.status) {
      case 'passed':
        return <CheckCircle2 className="h-4 w-4 text-[--color-accent-green]" />;
      case 'failed':
        return <span className="h-4 w-4 rounded-full bg-[--color-accent-red] inline-block" />;
      case 'errored':
        return <span className="h-4 w-4 rounded-full bg-[--color-accent-orange] inline-block" />;
      case 'skipped':
        return (
          <span
            className="h-4 w-4 rounded-full border border-[--color-text-muted] inline-block opacity-50"
            title="Skipped"
          />
        );
      case 'running':
        return <Loader2 className="h-4 w-4 animate-spin text-[--color-accent-blue]" />;
      default:
        return <span className="h-4 w-4 rounded-full bg-[--color-text-muted] inline-block" />;
    }
  };

  return (
    <div className="px-4 py-2.5 flex items-center gap-3 hover:bg-[--color-surface-hover] transition-colors">
      {statusIcon()}
      <span className="font-mono text-xs text-[--color-text-muted] w-20">{execution.check_id}</span>
      <span className="text-sm text-[--color-text-primary] flex-1 truncate">{execution.check_title}</span>
      <span className="font-mono text-xs text-[--color-text-muted] capitalize w-20 text-right">
        {(SERVICE_LABELS as Record<string, string>)[execution.service_category] || execution.service_category}
      </span>
      {execution.findings_count > 0 && (
        <span className="rounded bg-[--color-accent-red]/10 text-[--color-accent-red] px-2 py-0.5 text-xs font-mono">
          {execution.findings_count}
        </span>
      )}
      {execution.duration_ms > 0 && (
        <span className="font-mono text-xs text-[--color-text-muted] w-16 text-right">
          {execution.duration_ms}ms
        </span>
      )}
      {execution.error_message && (
        <span
          className={`text-xs truncate max-w-[280px] ${
            execution.status === 'skipped' ? 'text-[--color-text-muted]' : 'text-[--color-accent-red]'
          }`}
          title={execution.error_message}
        >
          {execution.error_message}
        </span>
      )}
    </div>
  );
}
