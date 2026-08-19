import { SEVERITY_COLORS } from '@/lib/types';
import type { Severity } from '@/lib/types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLORS[severity];
  return (
    <span
      className="mt-0.5 inline-block rounded px-2 py-0.5 text-xs font-mono font-bold uppercase shrink-0"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {severity}
    </span>
  );
}
