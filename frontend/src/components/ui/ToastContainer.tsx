import { X } from 'lucide-react';
import { useToastStore } from '@/stores/toastStore';

/**
 * Bottom-right stack of ephemeral notifications. Mounted once in Shell so
 * every page can push toasts without re-rendering them per-route.
 */
export function ToastContainer() {
  const { toasts, dismiss } = useToastStore();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col-reverse gap-2 max-w-sm">
      {toasts.map((t) => {
        const borderColor =
          t.variant === 'error'
            ? 'border-[--color-accent-red]/50'
            : t.variant === 'success'
              ? 'border-[--color-accent-green]/50'
              : 'border-[--color-accent-blue]/50';
        return (
          <div
            key={t.id}
            role="status"
            aria-live="polite"
            className={`pointer-events-auto rounded-lg border ${borderColor} bg-[--color-surface] shadow-lg px-4 py-3 flex items-start gap-3 animate-in slide-in-from-bottom-2`}
          >
            <div className="flex-1 text-sm text-[--color-text-primary]">{t.message}</div>
            {t.action && (
              <button
                onClick={() => {
                  t.action!.onClick();
                  dismiss(t.id);
                }}
                className="text-xs font-mono uppercase tracking-wider text-[--color-accent-green] hover:text-[#00e03a]"
              >
                {t.action.label}
              </button>
            )}
            <button
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              className="text-[--color-text-muted] hover:text-[--color-text-primary]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
