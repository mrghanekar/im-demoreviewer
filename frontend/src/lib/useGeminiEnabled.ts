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

/**
 * The `gcloud run services logs read ...` command for *this* deployment.
 *
 * The service name and region come from /health rather than being hardcoded:
 * the banner used to name asia-south1 unconditionally, so anyone who deployed
 * elsewhere was handed a command that reads the wrong service's logs, or none.
 * Falls back to omitting --region when the backend does not know it (a local
 * run, or a deployment from before setup.sh started passing DR_REGION).
 */
export function useLogsCommand(): string {
  const { data } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    staleTime: Infinity,
    retry: 1,
  });
  const service = data?.service_name || 'democratized-reviewer';
  const region = data?.region ? ` --region=${data.region}` : '';
  return `gcloud run services logs read ${service}${region} --limit=50`;
}
