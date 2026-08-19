/**
 * TypeScript types matching the backend Pydantic models.
 * Keep in sync with backend/core/models.py.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'reliability' | 'performance' | 'cost' | 'operations';
export type ServiceCategory =
  | 'gke' | 'gce' | 'gcs' | 'databases' | 'security'
  | 'networking' | 'iam' | 'data' | 'monitoring' | 'billing' | 'vertex_ai'
  | 'cloud_run' | 'cloud_functions' | 'secret_manager' | 'cloud_build'
  | 'memorystore' | 'firestore' | 'spanner' | 'iap' | 'composer' | 'posture'
  | 'alloydb' | 'app_engine' | 'cloud_run_jobs';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type CheckStatus = 'pending' | 'running' | 'passed' | 'failed' | 'errored' | 'skipped';
export type CostAnalysisStatus = 'pending' | 'running' | 'completed' | 'failed';

// ---------------------------------------------------------------------------
// Core Models
// ---------------------------------------------------------------------------

export interface Finding {
  id: string;
  scan_id: string;
  check_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  service: string;
  resource_name: string;
  resource_link: string;
  project_id: string;
  current_state: string;
  recommended_state: string;
  fix_command: string;
  references: string[];
  metadata: Record<string, unknown>;
  discovered_at: string;
  suppressed?: boolean;
  suppression_reason?: string;
  estimated_monthly_cost_usd?: number | null;
  cost_basis?: string;
}

export interface CheckExecution {
  check_id: string;
  check_title: string;
  service_category: ServiceCategory;
  status: CheckStatus;
  findings_count: number;
  error_message: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number;
}

export interface ScanSummary {
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_category: Record<Category, number>;
  by_service: Record<string, number>;
  checks_passed: number;
  checks_failed: number;
  checks_errored: number;
  checks_skipped: number;
  scan_duration_seconds: number;
  health_score?: number;
  health_grade?: 'A' | 'B' | 'C' | 'D' | 'F';
  estimated_monthly_waste_usd?: number;
}

export interface CostAnalysis {
  status: CostAnalysisStatus;
  model: string;
  started_at: string | null;
  completed_at: string | null;
  total_monthly_usd: number;
  findings_count: number;
  costed_count: number;
  grounding_sources: string[];
  notes: string;
  error_message: string;
}

export interface CostEstimate {
  findings_to_analyze: number;
  estimated_tokens_in: number;
  estimated_tokens_out: number;
  estimated_usd: number;
  model: string;
}

export interface Scan {
  id: string;
  scope: 'org' | 'project';
  target_id: string;
  status: ScanStatus;
  categories: ServiceCategory[];
  specific_projects?: string[];
  started_at: string | null;
  completed_at: string | null;
  summary: ScanSummary;
  findings: Finding[];
  check_executions: CheckExecution[];
  projects_scanned: string[];
  error_message: string;
  scan_token?: string;
  cost_analysis?: CostAnalysis | null;
}

export interface ScanRequest {
  scope: 'org' | 'project';
  target_id: string;
  categories: ServiceCategory[];
  specific_projects?: string[];
}

// ---------------------------------------------------------------------------
// Setup Models
// ---------------------------------------------------------------------------

export interface ServiceAccountInfo {
  email: string;
  project_id: string;
  default_org_id?: string;
  account_type: string;
  is_active: boolean;
}

export interface RoleValidation {
  valid: boolean;
  granted_roles: string[];
  missing_roles: string[];
  grant_commands: string[];
}

export interface ProjectInfo {
  project_id: string;
  name: string;
  project_number: string;
  state: string;
  parent_type: string;
  parent_id: string;
}

export interface OrganizationInfo {
  org_id: string;
  display_name: string;
  state: string;
}

export interface CheckCatalogEntry {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  service: string;
  service_category: ServiceCategory;
}

export interface HealthResponse {
  status: string;
  version: string;
  app_name: string;
  checks_loaded: number;
  environment: string;
  gemini_enabled?: boolean;
}

// ---------------------------------------------------------------------------
// WebSocket Events
// ---------------------------------------------------------------------------

export interface ScanEvent {
  event_type: string;
  scan_id: string;
  timestamp: string;
  data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// UI Helpers
// ---------------------------------------------------------------------------

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f85149',
  high: '#d29922',
  medium: '#58a6ff',
  low: '#8b949e',
  info: '#6e7681',
};

export const CATEGORY_COLORS: Record<Category, string> = {
  security: '#f85149',
  reliability: '#d29922',
  performance: '#58a6ff',
  cost: '#00ff41',
  operations: '#bc8cff',
};

export const SERVICE_LABELS: Record<ServiceCategory, string> = {
  gke: 'GKE',
  gce: 'GCE',
  gcs: 'GCS',
  databases: 'Cloud SQL',
  security: 'Security',
  networking: 'Networking',
  iam: 'IAM',
  data: 'Data Services',
  monitoring: 'Monitoring',
  billing: 'Billing',
  vertex_ai: 'Vertex AI',
  cloud_run: 'Cloud Run',
  cloud_functions: 'Cloud Functions',
  secret_manager: 'Secret Manager',
  cloud_build: 'Cloud Build',
  memorystore: 'Memorystore',
  firestore: 'Firestore',
  spanner: 'Spanner',
  iap: 'IAP',
  composer: 'Composer',
  posture: 'Architecture Posture',
  alloydb: 'AlloyDB',
  app_engine: 'App Engine',
  cloud_run_jobs: 'Cloud Run Jobs',
};

export const ALL_SERVICE_CATEGORIES: ServiceCategory[] = [
  'gke', 'gce', 'gcs', 'databases', 'security',
  'networking', 'iam', 'data', 'monitoring', 'billing', 'vertex_ai',
  'cloud_run', 'cloud_functions', 'secret_manager', 'cloud_build',
  'memorystore', 'firestore', 'spanner', 'iap', 'composer', 'posture',
  'alloydb', 'app_engine', 'cloud_run_jobs',
];
