import { useQuery } from '@tanstack/react-query';

import { fetchHealth } from './api';

/**
 * One-time fetch of /health to learn whether this deployment opted in to
 * Vertex AI / Gemini features. Returns `false` when the operator answered
 * "no" to the Vertex AI prompt during setup.sh.
 *
 * Default is `true` if the field is missing (older deployments that predate
 * the flag) — matches the backend default.
 *
 * TanStack Query dedupes by key, so calling this from N components costs
 * exactly one network request per session.
 */
export function useGeminiEnabled(): boolean {
  const { data } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    staleTime: Infinity,
    retry: 1,
  });
  return data?.gemini_enabled !== false;
}
