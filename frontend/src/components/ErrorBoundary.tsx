import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Catches render errors so a single bad component doesn't blank the SPA.
 *
 * Without this, an undefined deref anywhere in the tree unmounts everything
 * and the user is left staring at a white page with the failure only visible
 * in the browser console.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Unhandled render error:', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6">
        <div className="max-w-lg w-full rounded-lg border border-red-900/60 bg-slate-900 p-6">
          <h1 className="text-lg font-semibold text-red-400">Something went wrong</h1>
          <p className="mt-2 text-sm text-slate-300">
            The page failed to render. Your scan is unaffected — it keeps running
            on the server and the results are still available after a reload.
          </p>
          <pre className="mt-4 max-h-48 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-400">
            {error.message}
          </pre>
          <button
            type="button"
            className="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
            onClick={() => window.location.reload()}
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
