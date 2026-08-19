import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Terminal, Zap, Eye, FileText, UserCircle2, Sparkles } from 'lucide-react';
import { fetchServiceAccount } from '@/lib/api';
import type { ServiceAccountInfo } from '@/lib/types';
import { GlimmeringBackground } from '@/components/ui/GlimmeringBackground';
import { playRocketLaunchSound } from '@/lib/sound';

export function Home() {
  const [saInfo, setSaInfo] = useState<ServiceAccountInfo | null>(null);

  useEffect(() => {
    fetchServiceAccount().then(setSaInfo).catch(() => {});
  }, []);

  return (
    <>
    <GlimmeringBackground />
    <div className="relative z-10 mx-auto max-w-5xl px-4 py-16">
      {/* Hero */}
      <div className="text-center mb-16 pt-8">
        <h1 className="text-5xl md:text-7xl font-bold font-mono text-transparent bg-clip-text bg-gradient-to-r from-[--color-accent-green] via-emerald-400 to-[--color-accent-green] mb-6 drop-shadow-[0_0_10px_rgba(0,255,65,0.3)]">
          Democratized Reviewer
        </h1>
        <p className="text-xl text-[--color-text-secondary] max-w-2xl mx-auto mb-10 font-mono">
          <span className="text-[--color-accent-green] mr-2 opacity-60">$</span>
          Audit your Google Cloud environment against 199 best-practice checks.
        </p>

        {saInfo ? (
          <div className="mb-10 inline-flex items-center gap-3 rounded-full border border-[--color-accent-blue]/30 bg-[--color-surface] px-5 py-2.5 shadow-[0_0_15px_rgba(88,166,255,0.15)]">
            <UserCircle2 className="h-5 w-5 text-[--color-accent-blue]" />
            <div className="text-left">
              <div className="text-[10px] font-mono text-[--color-text-muted] uppercase tracking-wider leading-tight">Running As</div>
              <div className="font-mono text-xs font-medium text-[--color-text-primary]">
                {saInfo.email || 'Unknown Identity'}
              </div>
            </div>
            {saInfo.project_id && (
              <div className="border-l border-[--color-border] pl-4 text-left">
                <div className="text-[10px] font-mono text-[--color-text-muted] uppercase tracking-wider leading-tight">Project</div>
                <div className="font-mono text-xs font-medium text-[--color-text-primary]">{saInfo.project_id}</div>
              </div>
            )}
          </div>
        ) : (
          <div className="mb-10 h-12 w-80 mx-auto rounded-full bg-[--color-surface] animate-pulse"></div>
        )}

        <div className="flex flex-col items-center gap-3">
          <Link
            to="/scan"
            onClick={() => playRocketLaunchSound()}
            className="group relative inline-flex items-center gap-3 rounded-xl bg-[--color-accent-green] px-10 py-5 text-xl font-mono font-black text-black hover:bg-[#00e03a] hover:scale-[1.02] transition-all duration-200 shadow-[0_0_25px_rgba(0,255,65,0.3)] hover:shadow-[0_0_50px_rgba(0,255,65,0.5)] active:scale-95"
          >
            <span className="relative z-10 flex items-center gap-2">
              <Terminal className="h-6 w-6" />
              INITIATE_REVIEW_SEQUENCE
              <ArrowRight className="h-6 w-6 group-hover:translate-x-1 transition-transform" />
            </span>
          </Link>
          <Link
            to="/catalog"
            className="text-xs font-mono text-[--color-text-secondary] hover:text-[--color-accent-green] underline underline-offset-4"
          >
            or browse the 199-check catalog first →
          </Link>
        </div>
      </div>

      {/* Features grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-16">
        <FeatureCard
          icon={<Eye className="h-6 w-6 text-[--color-accent-blue]" />}
          title="Read-Only Scanning"
          description="All checks use viewer-only IAM roles. Your infrastructure is never modified. Safe to run in production."
        />
        <FeatureCard
          icon={<Zap className="h-6 w-6 text-[--color-accent-green]" />}
          title="Actionable Fixes"
          description="Every finding includes a copy-paste gcloud command to remediate. No guesswork required."
        />
        <FeatureCard
          icon={<Sparkles className="h-6 w-6 text-[--color-accent-purple]" />}
          title="AI-Powered Analysis"
          description="Uses Gemini to explain findings and provide context-aware remediation advice in plain English."
        />
        <FeatureCard
          icon={<FileText className="h-6 w-6 text-[--color-accent-orange]" />}
          title="Exportable Reports"
          description="Download results as PDF, JSON or HTML. Export to GCS for sharing with your team and stakeholders."
        />
      </div>

      {/* Service categories */}
      <div className="text-center mb-8">
        <h2 className="font-mono text-xl text-[--color-text-primary] mb-2">
          <span className="text-[--color-accent-green]">21</span> Service Categories
        </h2>
        <p className="text-[--color-text-secondary] text-sm">Comprehensive coverage across your GCP environment</p>
      </div>

      <div className="flex flex-wrap justify-center gap-3">
        {[
          'GKE', 'GCE', 'GCS', 'Databases', 'Security', 'Networking', 'IAM',
          'Data Services', 'Monitoring', 'Billing', 'Vertex AI', 'Cloud Run',
          'Cloud Functions', 'Secret Manager', 'Cloud Build', 'Memorystore',
          'Firestore', 'Spanner', 'IAP', 'Composer', 'Posture',
        ].map(
          (svc) => (
            <span
              key={svc}
              className="rounded-full border border-[--color-border] bg-[--color-surface] px-4 py-1.5 text-sm font-mono text-[--color-text-secondary]"
            >
              {svc}
            </span>
          ),
        )}
      </div>
    </div>
    </>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-lg border border-[--color-border] bg-[--color-surface] p-6 hover:border-[--color-text-muted] transition-colors">
      <div className="mb-3">{icon}</div>
      <h3 className="font-mono font-bold text-[--color-text-primary] mb-2">{title}</h3>
      <p className="text-sm text-[--color-text-secondary] leading-relaxed">{description}</p>
    </div>
  );
}
