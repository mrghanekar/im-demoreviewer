import { Link } from 'react-router-dom';
import { Terminal } from 'lucide-react';

export function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-32 text-center">
      <Terminal className="h-12 w-12 text-[--color-accent-red] mb-4" />
      <h1 className="font-mono text-4xl text-[--color-text-primary] mb-2">404</h1>
      <p className="font-mono text-[--color-text-secondary] mb-6">
        <span className="text-[--color-accent-red]">ERROR</span>: path not found in filesystem
      </p>
      <Link
        to="/"
        className="rounded-lg border border-[--color-border] bg-[--color-surface] px-4 py-2 font-mono text-sm text-[--color-accent-green] hover:border-[--color-accent-green] transition-colors"
      >
        cd /home
      </Link>
    </div>
  );
}
