/**
 * API client for the Democratized Reviewer backend.
 *
 * All API calls go through this module. The Vite dev server
 * proxies /api to the FastAPI backend (see vite.config.ts).
 */

import type {
  CheckCatalogEntry,
  CostAnalysis,
  CostEstimate,
  Finding,
  HealthResponse,
  OrganizationInfo,
  ProjectInfo,
  RoleValidation,
  Scan,
  ScanRequest,
  ScanSummary,
  ServiceAccountInfo,
} from './types';

const API_BASE = '/api/v1';

// ---------------------------------------------------------------------------
// Generic fetch wrapper
// ---------------------------------------------------------------------------

class ApiError extends Error {
  status: number;
  statusText: string;
  detail: string;

  constructor(status: number, statusText: string, detail: string) {
    super(`API Error ${status}: ${detail}`);
    this.name = 'ApiError';
    this.status = status;
    this.statusText = statusText;
    this.detail = detail;
  }
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errorBody = await response.json();
      detail = errorBody.detail || detail;
    } catch {
      // ignore JSON parse errors
    }
    throw new ApiError(response.status, response.statusText, detail);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export function fetchHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>('/health');
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export function fetchServiceAccount(): Promise<ServiceAccountInfo> {
  return apiFetch<ServiceAccountInfo>('/setup/service-account');
}

export function fetchProjects(orgId?: string): Promise<ProjectInfo[]> {
  const params = orgId ? `?org_id=${encodeURIComponent(orgId)}` : '';
  return apiFetch<ProjectInfo[]>(`/setup/projects${params}`);
}

export function fetchOrganizations(): Promise<OrganizationInfo[]> {
  return apiFetch<OrganizationInfo[]>('/setup/organizations');
}

export function validatePermissions(
  projectId: string,
  scope: 'org' | 'project' = 'project',
): Promise<RoleValidation> {
  return apiFetch<RoleValidation>(
    `/setup/validate?project_id=${encodeURIComponent(projectId)}&scope=${scope}`,
  );
}

export function fetchChecksCatalog(): Promise<CheckCatalogEntry[]> {
  return apiFetch<CheckCatalogEntry[]>('/setup/checks/catalog');
}

export interface ScanTargetValidation {
  ok: boolean;
  project: string;
  sa_email: string;
  checks: { name: string; passed: boolean; detail: string }[];
  suggested_command: string;
}

export function validateScanTarget(project: string): Promise<ScanTargetValidation> {
  return apiFetch<ScanTargetValidation>(
    `/setup/validate-scan-target?project=${encodeURIComponent(project)}`,
  );
}

export function fetchBuckets(projectId?: string): Promise<string[]> {
  const params = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
  return apiFetch<string[]>(`/setup/buckets${params}`);
}

export function createBucket(name: string, projectId?: string): Promise<{ status: string; name: string }> {
  const params = new URLSearchParams();
  params.set('name', name);
  if (projectId) params.set('project_id', projectId);
  return apiFetch<{ status: string; name: string }>(`/setup/buckets?${params.toString()}`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export function createScan(request: ScanRequest): Promise<Scan> {
  return apiFetch<Scan>('/scans', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export function fetchScans(): Promise<Scan[]> {
  return apiFetch<Scan[]>('/scans');
}

export function fetchScan(scanId: string): Promise<Scan> {
  return apiFetch<Scan>(`/scans/${scanId}`);
}

export function cancelScan(scanId: string): Promise<Scan> {
  return apiFetch<Scan>(`/scans/${scanId}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export function fetchFindings(
  scanId: string,
  filters?: { severity?: string; category?: string; service?: string; includeSuppressed?: boolean },
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.category) params.set('category', filters.category);
  if (filters?.service) params.set('service', filters.service);
  if (filters?.includeSuppressed) params.set('include_suppressed', 'true');
  const qs = params.toString();
  return apiFetch<Finding[]>(`/scans/${scanId}/findings${qs ? `?${qs}` : ''}`);
}

export function fetchFinding(scanId: string, findingId: string): Promise<Finding> {
  return apiFetch<Finding>(`/scans/${scanId}/findings/${findingId}`);
}

export function suppressFinding(
  scanId: string,
  findingId: string,
  reason: string = '',
): Promise<Finding> {
  return apiFetch<Finding>(`/scans/${scanId}/findings/${findingId}/suppress`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export function unsuppressFinding(scanId: string, findingId: string): Promise<Finding> {
  return apiFetch<Finding>(`/scans/${scanId}/findings/${findingId}/suppress`, {
    method: 'DELETE',
  });
}

export function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  return apiFetch<ScanSummary>(`/scans/${scanId}/summary`);
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export function exportToGcs(scanId: string, bucket: string): Promise<{ status: string; gcs_uri: string; files: string[] }> {
  return apiFetch(`/scans/${scanId}/export?bucket=${encodeURIComponent(bucket)}`, {
    method: 'POST',
  });
}

export function getExportJsonUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/export/json`;
}

export function getExportHtmlUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/export/html`;
}

export function getExportPdfUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/export/pdf`;
}

export function getExportCsvUrl(scanId: string, includeSuppressed: boolean = false): string {
  return `${API_BASE}/scans/${scanId}/export/csv${includeSuppressed ? '?include_suppressed=true' : ''}`;
}

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------

export function explainFinding(finding: Finding): Promise<{ explanation: string }> {
  return apiFetch<{ explanation: string }>('/ai/explain', {
    method: 'POST',
    body: JSON.stringify({ finding }),
  });
}

// ---------------------------------------------------------------------------
// Cost analysis (Gemini-powered, on-demand)
// ---------------------------------------------------------------------------

export function getCostEstimate(scanId: string): Promise<CostEstimate> {
  return apiFetch<CostEstimate>(`/cost/scans/${scanId}/cost-analysis/estimate`);
}

export function getCostAnalysis(scanId: string): Promise<CostAnalysis> {
  return apiFetch<CostAnalysis>(`/cost/scans/${scanId}/cost-analysis`);
}

export function startCostAnalysis(scanId: string, force: boolean = false): Promise<CostAnalysis> {
  const qs = force ? '?force=true' : '';
  return apiFetch<CostAnalysis>(`/cost/scans/${scanId}/cost-analysis${qs}`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// Re-export error class
// ---------------------------------------------------------------------------

export { ApiError };
