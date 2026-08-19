import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScanStore } from '@/stores/scanStore';
import { fetchServiceAccount, fetchOrganizations, fetchProjects, validateScanTarget } from '@/lib/api';
import { ALL_SERVICE_CATEGORIES, SERVICE_LABELS } from '@/lib/types';
import { playInitSound } from '@/lib/sound';
import type { ServiceCategory } from '@/lib/types';
import {
  ChevronRight,
  Building2,
  FolderKanban,
  CheckCircle2,
  Circle,
  Loader2,
  Play,
  Check,
} from 'lucide-react';

type WizardStep = 'scope' | 'target' | 'projects' | 'categories' | 'launch';
const STEPS: WizardStep[] = ['scope', 'target', 'projects', 'categories', 'launch'];
const STEP_LABELS: Record<WizardStep, string> = {
  scope: 'Scope',
  target: 'Target',
  projects: 'Projects',
  categories: 'Categories',
  launch: 'Launch',
};

export function Scan() {
  const [step, setStep] = useState<WizardStep>('scope');
  const navigate = useNavigate();

  const {
    scope, setScope,
    targetId, setTargetId,
    selectedCategories, setCategories,
    selectedProjects, setSelectedProjects,
    startScan, isScanning, scanError,
  } = useScanStore();

  const [availableProjects, setAvailableProjects] = useState<{id: string, name: string}[]>([]);
  const [isLoadingProjects, setIsLoadingProjects] = useState(false);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [saInfo, setSaInfo] = useState<{project_id: string, default_org_id?: string} | null>(null);
  // Pre-flight scan-target validation state.
  const [preflightChecking, setPreflightChecking] = useState(false);
  const [preflightError, setPreflightError] = useState<{ message: string; command: string } | null>(null);

  // Fetch SA info once on mount
  useEffect(() => {
    fetchServiceAccount().then(setSaInfo).catch(console.error);
  }, []);

  // Auto-fill target ID based on scope
  useEffect(() => {
    if (scope === 'project' && !targetId && saInfo?.project_id) {
      console.log('Auto-filled project ID:', saInfo.project_id);
      setTargetId(saInfo.project_id);
    } else if (scope === 'org' && !targetId) {
      if (saInfo?.default_org_id) {
        console.log('Auto-filled Org ID from env:', saInfo.default_org_id);
        setTargetId(saInfo.default_org_id);
      } else {
        console.log('Fetching organizations for auto-fill...');
        fetchOrganizations()
          .then((orgs) => {
            if (orgs && orgs.length > 0) {
              console.log('Auto-filled Org ID from API:', orgs[0].org_id);
              setTargetId(orgs[0].org_id);
            } else {
              console.warn('No organizations returned by API');
            }
          })
          .catch((err) => console.error('Failed to fetch orgs:', err));
      }
    }
  }, [scope, targetId, setTargetId, saInfo]);

  // Fetch projects when entering 'projects' step.
  // Uses an `ignore` flag so a stale fetch (e.g. user changed targetId mid-flight)
  // can't overwrite state with the wrong project list.
  useEffect(() => {
    if (step !== 'projects' || scope !== 'org' || !targetId) return;

    let ignore = false;
    setIsLoadingProjects(true);
    setProjectsError(null);
    fetchProjects(targetId)
      .then((projects) => {
        if (ignore) return;
        setAvailableProjects(projects.map(p => ({ id: p.project_id, name: p.name })));
        if (selectedProjects.length === 0) {
          setSelectedProjects(projects.map(p => p.project_id));
        }
      })
      .catch((err) => {
        if (ignore) return;
        setProjectsError('Failed to fetch projects. Please ensure the service account has Organization Viewer permissions.');
        console.error(err);
      })
      .finally(() => {
        if (!ignore) setIsLoadingProjects(false);
      });

    return () => { ignore = true; };
  }, [step, scope, targetId, selectedProjects.length, setSelectedProjects]);

  // Filter steps based on scope (skip 'projects' if scope is project)
  const activeSteps = STEPS.filter(s => s !== 'projects' || scope === 'org');
  const currentStepIndex = activeSteps.indexOf(step);

  const goNext = () => {
    const idx = activeSteps.indexOf(step);
    if (idx < activeSteps.length - 1) setStep(activeSteps[idx + 1]);
  };

  const goPrev = () => {
    const idx = activeSteps.indexOf(step);
    if (idx > 0) setStep(activeSteps[idx - 1]);
  };

  const handleLaunch = async () => {
    // Pre-flight: confirm the SA can actually read the scan target before we
    // kick off a scan that would otherwise 403 and waste 30s per check.
    if (scope === 'project' && targetId) {
      setPreflightError(null);
      setPreflightChecking(true);
      try {
        const v = await validateScanTarget(targetId);
        if (!v.ok) {
          const failures = v.checks.filter((c) => !c.passed).map((c) => c.name).join(', ');
          setPreflightError({
            message: `Service account can't read ${v.project} (failing probes: ${failures}). Grant it viewer roles, then click Launch again.`,
            command: v.suggested_command,
          });
          setPreflightChecking(false);
          return;
        }
      } catch (err) {
        // Don't block on probe-endpoint errors — the scan itself will surface
        // the real issue. Just log and continue.
        console.warn('Pre-flight validation failed (continuing):', err);
      } finally {
        setPreflightChecking(false);
      }
    }
    playInitSound();
    await startScan();
    const scanId = useScanStore.getState().currentScanId;
    if (scanId) {
      navigate(`/results/${scanId}`);
    }
  };

  const toggleCategory = (cat: ServiceCategory) => {
    if (selectedCategories.includes(cat)) {
      setCategories(selectedCategories.filter((c) => c !== cat));
    } else {
      setCategories([...selectedCategories, cat]);
    }
  };

  const toggleAllCategories = () => {
    if (selectedCategories.length === ALL_SERVICE_CATEGORIES.length) {
      setCategories([]);
    } else {
      setCategories([...ALL_SERVICE_CATEGORIES]);
    }
  };
  
  const toggleProject = (pid: string) => {
    if (selectedProjects.includes(pid)) {
      setSelectedProjects(selectedProjects.filter(p => p !== pid));
    } else {
      setSelectedProjects([...selectedProjects, pid]);
    }
  };

  const toggleAllProjects = () => {
    if (selectedProjects.length === availableProjects.length) {
      setSelectedProjects([]);
    } else {
      setSelectedProjects(availableProjects.map(p => p.id));
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-4 py-12">
      {/* Step indicator */}
      <div className="flex items-center justify-center gap-2 mb-12">
        {activeSteps.map((s, i) => (
          <div key={s} className="flex items-center gap-2">
            <button
              onClick={() => i <= currentStepIndex ? setStep(s) : undefined}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono transition-colors ${
                s === step
                  ? 'bg-[--color-accent-green] text-black font-bold'
                  : i < currentStepIndex
                  ? 'bg-[--color-surface] text-[--color-accent-green] border border-[--color-accent-green] cursor-pointer'
                  : 'bg-[--color-surface] text-[--color-text-muted] border border-[--color-border]'
              }`}
            >
              {i < currentStepIndex ? (
                <CheckCircle2 className="h-3 w-3" />
              ) : (
                <Circle className="h-3 w-3" />
              )}
              {STEP_LABELS[s]}
            </button>
            {i < activeSteps.length - 1 && (
              <ChevronRight className="h-4 w-4 text-[--color-text-muted]" />
            )}
          </div>
        ))}
      </div>

      {/* Step content */}
      <div className="rounded-lg border border-[--color-border] bg-[--color-surface] p-8">
        {step === 'scope' && (
          <div>
            <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
              Select Scan Scope
            </h2>
            <p className="text-sm text-[--color-text-secondary] mb-6">
              Choose whether to scan an entire organization or a single project.
            </p>
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => { setScope('org'); setTargetId(''); goNext(); }}
                className={`flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-colors ${
                  scope === 'org'
                    ? 'border-[--color-accent-green] bg-[--color-accent-green]/5'
                    : 'border-[--color-border] hover:border-[--color-text-muted]'
                }`}
              >
                <Building2 className="h-8 w-8 text-[--color-accent-blue]" />
                <span className="font-mono font-bold text-[--color-text-primary]">Organization</span>
                <span className="text-xs text-[--color-text-secondary] text-center">
                  Scan all projects under an org
                </span>
              </button>
              <button
                onClick={() => { setScope('project'); setTargetId(''); goNext(); }}
                className={`flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-colors ${
                  scope === 'project'
                    ? 'border-[--color-accent-green] bg-[--color-accent-green]/5'
                    : 'border-[--color-border] hover:border-[--color-text-muted]'
                }`}
              >
                <FolderKanban className="h-8 w-8 text-[--color-accent-purple]" />
                <span className="font-mono font-bold text-[--color-text-primary]">Project</span>
                <span className="text-xs text-[--color-text-secondary] text-center">
                  Scan a single GCP project
                </span>
              </button>
            </div>
          </div>
        )}

        {step === 'target' && (
          <div>
            <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
              Enter {scope === 'org' ? 'Organization' : 'Project'} ID
            </h2>
            <p className="text-sm text-[--color-text-secondary] mb-6">
              {scope === 'org'
                ? 'Enter your GCP organization ID (numeric).'
                : 'Enter the GCP project ID to scan.'}
            </p>
            <input
              type="text"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && targetId.trim()) {
                  goNext();
                }
              }}
              placeholder={scope === 'org' ? '123456789012' : 'my-gcp-project-id'}
              className="w-full rounded-lg border border-[--color-border] bg-[#161b22] px-4 py-3 font-mono text-sm text-white placeholder:text-[--color-text-muted] focus:border-[--color-accent-green] focus:outline-none focus:ring-1 focus:ring-[--color-accent-green] transition-colors"
            />
            <div className="flex justify-between mt-6">
              <button onClick={goPrev} className="text-sm text-[--color-text-secondary] hover:text-[--color-text-primary]">
                Back
              </button>
              <button
                onClick={goNext}
                disabled={!targetId.trim()}
                className="rounded-lg bg-[--color-accent-green] px-4 py-2 font-mono text-sm font-bold text-white disabled:opacity-50 hover:opacity-90 transition-opacity"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 'projects' && (
          <div>
            <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
              Select Projects
            </h2>
            <p className="text-sm text-[--color-text-secondary] mb-4">
              Select the projects within the organization to include in the scan.
            </p>
            
            {isLoadingProjects ? (
               <div className="py-12 flex flex-col items-center justify-center text-[--color-text-muted]">
                 <Loader2 className="h-8 w-8 animate-spin mb-3 text-[--color-accent-green]" />
                 <span>Fetching projects from Organization...</span>
               </div>
            ) : projectsError ? (
               <div className="rounded border border-[--color-accent-red] bg-[--color-accent-red]/10 p-4 mb-4 text-sm text-[--color-accent-red]">
                 {projectsError}
                 <button onClick={() => window.location.reload()} className="block mt-2 font-bold hover:underline">Retry</button>
               </div>
            ) : (
               <>
                <button
                  onClick={toggleAllProjects}
                  className="mb-4 text-xs font-mono text-[--color-accent-blue] hover:underline"
                >
                  {selectedProjects.length === availableProjects.length ? 'Deselect All' : 'Select All'}
                </button>
                <div className="max-h-[300px] overflow-y-auto rounded-lg border border-[--color-border] bg-[--color-background]">
                  {availableProjects.length === 0 ? (
                    <div className="p-4 text-center text-[--color-text-muted] text-sm">No projects found.</div>
                  ) : (
                    availableProjects.map((proj) => (
                      <button
                        key={proj.id}
                        onClick={() => toggleProject(proj.id)}
                        className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors border-b border-[--color-border-light] last:border-0 hover:bg-[--color-surface-hover] ${
                           selectedProjects.includes(proj.id) ? 'bg-[--color-accent-green]/5' : ''
                        }`}
                      >
                         <div
                            className={`h-4 w-4 rounded border flex items-center justify-center shrink-0 ${
                              selectedProjects.includes(proj.id)
                                ? 'border-[--color-accent-green] bg-[--color-accent-green]'
                                : 'border-[--color-border]'
                            }`}
                          >
                            {selectedProjects.includes(proj.id) && (
                              <Check className="h-3 w-3 text-white" />
                            )}
                          </div>
                          <div>
                            <div className="text-sm text-[--color-text-primary] font-mono">{proj.id}</div>
                            {proj.name && <div className="text-xs text-[--color-text-muted]">{proj.name}</div>}
                          </div>
                      </button>
                    ))
                  )}
                </div>
               </>
            )}

            <div className="flex justify-between mt-6">
              <button onClick={goPrev} className="text-sm text-[--color-text-secondary] hover:text-[--color-text-primary]">
                Back
              </button>
              <button
                onClick={goNext}
                disabled={selectedProjects.length === 0 || isLoadingProjects}
                className="rounded-lg bg-[--color-accent-green] px-4 py-2 font-mono text-sm font-bold text-white disabled:opacity-50 hover:opacity-90 transition-opacity"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 'categories' && (
          <div>
            <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
              Select Check Categories
            </h2>
            <p className="text-sm text-[--color-text-secondary] mb-4">
              Choose which service categories to include in the scan.
            </p>
            <button
              onClick={toggleAllCategories}
              className="mb-4 text-xs font-mono text-[--color-accent-blue] hover:underline"
            >
              {selectedCategories.length === ALL_SERVICE_CATEGORIES.length ? 'Deselect All' : 'Select All'}
            </button>
            <div className="grid grid-cols-2 gap-3">
              {ALL_SERVICE_CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => toggleCategory(cat)}
                  className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
                    selectedCategories.includes(cat)
                      ? 'border-[--color-accent-green] bg-[--color-accent-green]/5'
                      : 'border-[--color-border] hover:border-[--color-text-muted]'
                  }`}
                >
                  <div
                    className={`h-4 w-4 rounded border flex items-center justify-center ${
                      selectedCategories.includes(cat)
                        ? 'border-[--color-accent-green] bg-[--color-accent-green]'
                        : 'border-[--color-border]'
                    }`}
                  >
                    {selectedCategories.includes(cat) && (
                      <Check className="h-3 w-3 text-white" />
                    )}
                  </div>
                  <span className="font-mono text-sm text-[--color-text-primary]">
                    {SERVICE_LABELS[cat]}
                  </span>
                </button>
              ))}
            </div>
            <div className="flex justify-between mt-6">
              <button onClick={goPrev} className="text-sm text-[--color-text-secondary] hover:text-[--color-text-primary]">
                Back
              </button>
              <button
                onClick={goNext}
                disabled={selectedCategories.length === 0}
                className="rounded-lg bg-[--color-accent-green] px-4 py-2 font-mono text-sm font-bold text-white disabled:opacity-50 hover:opacity-90 transition-opacity"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 'launch' && (
          <div>
            <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
              Review & Launch
            </h2>
            <p className="text-sm text-[--color-text-secondary] mb-6">
              Confirm your scan configuration.
            </p>

            <div className="space-y-3 mb-6">
              <div className="flex justify-between rounded border border-[--color-border] bg-[--color-background] px-4 py-2">
                <span className="text-sm text-[--color-text-secondary]">Scope</span>
                <span className="font-mono text-sm text-[--color-text-primary]">{scope}</span>
              </div>
              <div className="flex justify-between rounded border border-[--color-border] bg-[--color-background] px-4 py-2">
                <span className="text-sm text-[--color-text-secondary]">Target</span>
                <span className="font-mono text-sm text-[--color-text-primary]">{targetId}</span>
              </div>
              {scope === 'org' && (
                <div className="flex justify-between rounded border border-[--color-border] bg-[--color-background] px-4 py-2">
                  <span className="text-sm text-[--color-text-secondary]">Projects</span>
                  <span className="font-mono text-sm text-[--color-text-primary]">{selectedProjects.length} selected</span>
                </div>
              )}
              <div className="flex justify-between rounded border border-[--color-border] bg-[--color-background] px-4 py-2">
                <span className="text-sm text-[--color-text-secondary]">Categories</span>
                <span className="font-mono text-sm text-[--color-text-primary]">{selectedCategories.length} selected</span>
              </div>
            </div>

            {scanError && (
              <div className="mb-4 rounded border border-[--color-accent-red] bg-[--color-accent-red]/10 px-4 py-2 text-sm text-[--color-accent-red]">
                {scanError}
              </div>
            )}

            {preflightError && (
              <div className="mb-4 rounded border border-[--color-accent-orange] bg-[--color-accent-orange]/10 p-4 text-sm">
                <div className="font-mono text-xs uppercase tracking-wider text-[--color-accent-orange] mb-2">
                  Pre-flight check failed
                </div>
                <div className="text-[--color-text-primary] mb-3">{preflightError.message}</div>
                {preflightError.command && (
                  <>
                    <div className="text-xs text-[--color-text-muted] mb-1">Run this in Cloud Shell, then click Launch again:</div>
                    <pre className="rounded bg-[--color-background] border border-[--color-border-light] px-3 py-2 text-xs font-mono text-[--color-accent-green] overflow-x-auto whitespace-pre">
{preflightError.command}
                    </pre>
                  </>
                )}
              </div>
            )}

            <div className="flex justify-between">
              <button onClick={goPrev} className="text-sm text-[--color-text-secondary] hover:text-[--color-text-primary]">
                Back
              </button>
              <button
                onClick={handleLaunch}
                disabled={isScanning || preflightChecking}
                className="inline-flex items-center gap-2 rounded-lg bg-[--color-accent-green] px-6 py-3 font-mono font-bold text-white disabled:opacity-50 hover:opacity-90 transition-opacity"
              >
                {preflightChecking ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Validating target...
                  </>
                ) : isScanning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Start Scan
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
