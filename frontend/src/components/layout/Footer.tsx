export function Footer() {
  return (
    <footer className="border-t border-[--color-border] bg-[--color-surface] py-4">
      <div className="mx-auto max-w-7xl px-4 text-center text-xs text-[--color-text-muted] font-mono">
        <span className="text-[--color-accent-green]">$</span>{' '}
        democratized-reviewer v0.1.0 | read-only viewer access | scans never mutate your environment
      </div>
    </footer>
  );
}
