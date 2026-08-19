import { Github } from 'lucide-react';
import { Link } from 'react-router-dom';

export function Header() {
  return (
    <header className="border-b border-[--color-border] bg-[--color-surface]">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
        <Link to="/" className="flex items-center gap-2 text-[--color-accent-green] hover:opacity-80 transition-opacity">
          <img src="/logo.svg" alt="Logo" className="h-6 w-6" />
          <span className="font-semibold text-sm tracking-wide text-[--color-text-primary]">
            Democratized Reviewer
          </span>
        </Link>

        <nav className="flex items-center gap-6">
          <a
            href="https://gitlab.com/aghanekar/democratized-reviewer"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[--color-text-secondary] hover:text-[--color-text-primary] transition-colors"
          >
            <Github className="h-5 w-5" />
          </a>
        </nav>
      </div>
    </header>
  );
}
