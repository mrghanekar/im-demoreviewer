import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Download,
  FileJson,
  FileText,
  Cloud,
  CheckCircle,
  AlertCircle,
  Loader2,
  ExternalLink,
  ArrowLeft,
  Plus,
  RefreshCw,
} from 'lucide-react';

import { fetchScan, getExportJsonUrl, getExportHtmlUrl, getExportPdfUrl, exportToGcs, fetchBuckets, createBucket } from '@/lib/api';

export function Export() {
  const { scanId } = useParams<{ scanId: string }>();

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => fetchScan(scanId!),
    enabled: !!scanId,
  });

  const [gcsBucket, setGcsBucket] = useState('');
  const [gcsExporting, setGcsExporting] = useState(false);
  const [gcsResult, setGcsResult] = useState<{ status: string; gcs_uri: string; files: string[] } | null>(null);
  const [gcsError, setGcsError] = useState('');
  
  // Bucket management
  const [isCreatingBucket, setIsCreatingBucket] = useState(false);
  const [newBucketName, setNewBucketName] = useState('');
  const [bucketError, setBucketError] = useState('');

  const projectId = scan?.scope === 'project' ? scan.target_id : undefined;
  const { data: buckets = [], isLoading: isBucketsLoading, refetch: refetchBuckets } = useQuery({
    queryKey: ['buckets', projectId],
    queryFn: () => fetchBuckets(projectId),
    enabled: !!scan,
    retry: false,
  });

  const handleCreateBucket = async () => {
    if (!newBucketName.trim()) return;
    // Basic validation
    if (!/^[a-z0-9][a-z0-9._-]*[a-z0-9]$/.test(newBucketName.trim())) {
      setBucketError('Invalid bucket name. Use lowercase, numbers, hyphens.');
      return;
    }

    setGcsExporting(true);
    setBucketError('');
    try {
      await createBucket(newBucketName.trim(), projectId);
      await refetchBuckets();
      setGcsBucket(newBucketName.trim());
      setIsCreatingBucket(false);
      setNewBucketName('');
    } catch (err) {
      setBucketError(err instanceof Error ? err.message : 'Failed to create bucket');
    } finally {
      setGcsExporting(false);
    }
  };

  const handleGcsExport = async () => {
    if (!scanId || !gcsBucket.trim()) return;
    setGcsExporting(true);
    setGcsError('');
    setGcsResult(null);
    try {
      const result = await exportToGcs(scanId, gcsBucket.trim());
      setGcsResult(result);
    } catch (err) {
      setGcsError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setGcsExporting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-terminal-green animate-spin" />
        <span className="ml-2 text-muted">Loading scan data...</span>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12 text-muted">
        Scan not found. <Link to="/" className="text-terminal-green underline">Go home</Link>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <Link
          to={`/results/${scanId}`}
          className="inline-flex items-center gap-1 text-sm text-muted hover:text-terminal-green transition-colors mb-4"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Results
        </Link>
        <h1 className="text-2xl font-mono font-bold text-terminal-green">
          // EXPORT RESULTS
        </h1>
        <p className="text-muted text-sm mt-1">
          Scan <code className="text-xs">{scan.id}</code> &bull;{' '}
          {scan.summary.total_findings} findings
        </p>
      </div>

      {/* Download Section */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-blue-400 border-b border-dark-border pb-2">
          Download
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* JSON Download */}
          <a
            href={getExportJsonUrl(scanId!)}
            download
            className="group flex items-start gap-4 p-5 bg-dark-card border border-dark-border rounded-lg hover:border-terminal-green transition-colors"
          >
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 group-hover:bg-terminal-green/10 group-hover:text-terminal-green transition-colors">
              <FileJson className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground group-hover:text-terminal-green transition-colors">
                JSON Report
              </h3>
              <p className="text-sm text-muted mt-0.5">
                Full scan data as structured JSON. Ideal for programmatic analysis and CI/CD pipelines.
              </p>
            </div>
            <Download className="w-5 h-5 text-muted ml-auto mt-1 opacity-0 group-hover:opacity-100 transition-opacity" />
          </a>

          {/* HTML Download */}
          <a
            href={getExportHtmlUrl(scanId!)}
            download
            className="group flex items-start gap-4 p-5 bg-dark-card border border-dark-border rounded-lg hover:border-terminal-green transition-colors"
          >
            <div className="p-2 rounded-lg bg-orange-500/10 text-orange-400 group-hover:bg-terminal-green/10 group-hover:text-terminal-green transition-colors">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground group-hover:text-terminal-green transition-colors">
                HTML Report
              </h3>
              <p className="text-sm text-muted mt-0.5">
                Self-contained HTML with charts and filters. Share with stakeholders or print.
              </p>
            </div>
            <Download className="w-5 h-5 text-muted ml-auto mt-1 opacity-0 group-hover:opacity-100 transition-opacity" />
          </a>

          {/* PDF Download */}
          <button
            onClick={() => window.open(getExportPdfUrl(scanId!), '_blank')}
            className="group flex items-start text-left gap-4 p-5 bg-dark-card border border-dark-border rounded-lg hover:border-terminal-green transition-colors"
          >
            <div className="p-2 rounded-lg bg-red-500/10 text-red-400 group-hover:bg-terminal-green/10 group-hover:text-terminal-green transition-colors">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground group-hover:text-terminal-green transition-colors">
                PDF Report
              </h3>
              <p className="text-sm text-muted mt-0.5">
                Generate a printer-friendly PDF document. (Opens HTML report for printing).
              </p>
            </div>
            <ExternalLink className="w-5 h-5 text-muted ml-auto mt-1 opacity-0 group-hover:opacity-100 transition-opacity" />
          </button>
        </div>
      </section>

      {/* GCS Export Section */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-blue-400 border-b border-dark-border pb-2">
          Export to GCS
        </h2>
        <div className="bg-dark-card border border-dark-border rounded-lg p-5 space-y-4">
          <div className="flex items-start gap-4">
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <Cloud className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-foreground">Google Cloud Storage</h3>
              <p className="text-sm text-muted mt-0.5">
                Upload summary, findings, and HTML report to a GCS bucket for archival and sharing.
              </p>
            </div>
          </div>

          <div className="flex gap-2 items-start">
            <div className="relative flex-1">
              <span className="absolute left-3 top-2.5 text-muted text-sm font-mono">gs://</span>
              
              {isCreatingBucket ? (
                <div className="space-y-1">
                  <input
                    type="text"
                    value={newBucketName}
                    onChange={(e) => setNewBucketName(e.target.value)}
                    placeholder="new-bucket-name"
                    className="w-full pl-12 pr-3 py-2 bg-dark-bg border border-dark-border rounded-md text-sm font-mono text-foreground placeholder-muted focus:outline-none focus:border-terminal-green"
                    autoFocus
                  />
                  {bucketError && <p className="text-xs text-red-400">{bucketError}</p>}
                </div>
              ) : (
                <select
                  value={gcsBucket}
                  onChange={(e) => setGcsBucket(e.target.value)}
                  className="w-full pl-12 pr-10 py-2 bg-[#0d1117] border border-dark-border rounded-md text-sm font-mono text-white focus:outline-none focus:border-terminal-green appearance-none cursor-pointer"
                  disabled={isBucketsLoading}
                >
                  <option value="">Select a bucket...</option>
                  {buckets.map((b) => (
                    <option key={b} value={b}>{b}</option>
                  ))}
                </select>
              )}
            </div>

            {isCreatingBucket ? (
              <>
                <button
                  onClick={handleCreateBucket}
                  disabled={gcsExporting || !newBucketName.trim()}
                  className="px-3 py-2 bg-terminal-green text-black text-sm font-bold rounded-md hover:bg-terminal-green/90 disabled:opacity-50"
                >
                  Create
                </button>
                <button
                  onClick={() => { setIsCreatingBucket(false); setBucketError(''); }}
                  className="px-3 py-2 border border-dark-border text-muted text-sm rounded-md hover:text-foreground hover:border-text-primary"
                >
                  Cancel
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => setIsCreatingBucket(true)}
                  className="px-3 py-2 border border-dark-border text-muted hover:text-foreground hover:border-terminal-green rounded-md"
                  title="Create new bucket"
                >
                  <Plus className="w-4 h-4" />
                </button>
                <button
                  onClick={() => refetchBuckets()}
                  className="px-3 py-2 border border-dark-border text-muted hover:text-foreground hover:border-terminal-green rounded-md"
                  title="Refresh buckets"
                >
                  <RefreshCw className={`w-4 h-4 ${isBucketsLoading ? 'animate-spin' : ''}`} />
                </button>
              </>
            )}

            {!isCreatingBucket && (
              <button
                onClick={handleGcsExport}
                disabled={gcsExporting || !gcsBucket.trim()}
                className="px-4 py-2 bg-terminal-green/10 border border-terminal-green text-terminal-green text-sm font-mono rounded-md hover:bg-terminal-green/20 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-colors ml-2"
              >
                {gcsExporting ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Exporting...</>
                ) : (
                  <><Cloud className="w-4 h-4" /> Export</>
                )}
              </button>
            )}
          </div>

          {/* GCS Success */}
          {gcsResult && (
            <div className="bg-green-500/10 border border-green-500/30 rounded-md p-4 space-y-2">
              <div className="flex items-center gap-2 text-green-400">
                <CheckCircle className="w-4 h-4" />
                <span className="font-semibold text-sm">Export complete</span>
              </div>
              <p className="text-sm text-muted font-mono">{gcsResult.gcs_uri}</p>
              <div className="flex flex-wrap gap-2 mt-2">
                {gcsResult.files.map((f) => (
                  <a
                    key={f}
                    href={`https://console.cloud.google.com/storage/browser/${f.replace('gs://', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline"
                  >
                    {f.split('/').pop()} <ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* GCS Error */}
          {gcsError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-md p-4">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-4 h-4" />
                <span className="text-sm">{gcsError}</span>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
