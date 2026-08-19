export function StatCard({
  label,
  value,
  color,
  onClick,
  active,
}: {
  label: string;
  value: number | string;
  color?: string;
  onClick?: () => void;
  active?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={`rounded-lg border p-4 text-center w-full transition-colors ${
        active
          ? 'border-[--color-accent-blue] bg-[--color-accent-blue]/10'
          : 'border-[--color-border] bg-[--color-surface] hover:border-[--color-text-muted]'
      } ${!onClick ? 'cursor-default' : 'cursor-pointer'}`}
    >
      <div className={`text-2xl font-mono font-bold ${color || 'text-[--color-text-primary]'}`}>{value}</div>
      <div className="text-xs text-[--color-text-muted] mt-1">{label}</div>
    </button>
  );
}
