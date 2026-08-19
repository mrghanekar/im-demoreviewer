/**
 * Minimal toast store. Avoids an external dep — we just need ephemeral
 * notifications with an optional action button (currently used for Undo on
 * the suppress/unsuppress flow).
 */

import { create } from 'zustand';

export interface Toast {
  id: number;
  message: string;
  variant: 'info' | 'success' | 'error';
  action?: { label: string; onClick: () => void };
  /** Milliseconds before auto-dismiss; pass 0 to require manual close. */
  durationMs: number;
}

interface ToastState {
  toasts: Toast[];
  push: (toast: Omit<Toast, 'id' | 'durationMs'> & { durationMs?: number }) => number;
  dismiss: (id: number) => void;
}

let _seq = 0;

export const useToastStore = create<ToastState>((set, get) => ({
  toasts: [],
  push: (input) => {
    const id = ++_seq;
    const durationMs = input.durationMs ?? 5_000;
    const toast: Toast = { id, durationMs, variant: input.variant, message: input.message, action: input.action };
    set({ toasts: [...get().toasts, toast] });
    if (durationMs > 0) {
      setTimeout(() => get().dismiss(id), durationMs);
    }
    return id;
  },
  dismiss: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
}));
