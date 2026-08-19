/**
 * Big "letter grade + score" card surfaced at the top of Results.
 * Color reflects the grade band so a quick glance tells you whether to celebrate
 * or schedule a remediation sprint.
 */
export function HealthScoreCard({
  score,
  grade,
}: {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | string;
}) {
  const palette: Record<string, { fg: string; bg: string; label: string }> = {
    A: { fg: '#00ff41', bg: 'rgba(0,255,65,0.10)', label: 'Excellent' },
    B: { fg: '#7ee787', bg: 'rgba(126,231,135,0.10)', label: 'Good' },
    C: { fg: '#d4a72c', bg: 'rgba(212,167,44,0.10)', label: 'Needs work' },
    D: { fg: '#f7884a', bg: 'rgba(247,136,74,0.12)', label: 'At risk' },
    F: { fg: '#ff4d4f', bg: 'rgba(255,77,79,0.12)', label: 'Critical' },
  };
  const colors = palette[grade] || palette.A;

  return (
    <div
      className="rounded-lg border p-5 flex items-center gap-5"
      style={{ borderColor: `${colors.fg}40`, backgroundColor: colors.bg }}
    >
      <div className="flex flex-col items-center justify-center">
        <span className="font-mono text-6xl font-black leading-none" style={{ color: colors.fg }}>
          {grade}
        </span>
        <span className="font-mono text-xs uppercase tracking-wider text-[--color-text-muted] mt-1">
          {colors.label}
        </span>
      </div>
      <div className="flex-1">
        <div className="text-xs font-mono text-[--color-text-muted] uppercase tracking-wider">
          Health Score
        </div>
        <div className="text-3xl font-mono font-bold text-[--color-text-primary] mt-1">
          {score}
          <span className="text-base font-normal text-[--color-text-muted] ml-1">/ 100</span>
        </div>
        <div className="text-xs text-[--color-text-secondary] mt-2 max-w-xl">
          100 − (10×critical + 5×high + 2×medium + 0.5×low). Suppressed findings don't count.
          Grades: A 90+ · B 80+ · C 70+ · D 60+ · F &lt; 60.
        </div>
      </div>
    </div>
  );
}
