'use client';

import React, { useEffect, useState } from 'react';
import { Users, ThumbsUp, ThumbsDown, Plus, AlertCircle, CheckCircle, Globe } from 'lucide-react';
import { fetchCommunityReports, submitCommunityReport, voteCommunityReport } from '@/lib/api';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IThreatReport, ThreatCategoryEnum, type ThreatCategory } from '@sentrix/shared';

export default function CommunityPage() {
  const [reports, setReports] = useState<IThreatReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [url, setUrl] = useState('');
  const [category, setCategory] = useState<ThreatCategory>(ThreatCategoryEnum.PHISHING);
  const [description, setDescription] = useState('');
  const [submitterEmail, setSubmitterEmail] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const loadReports = () => {
    setLoading(true);
    fetchCommunityReports()
      .then((data) => {
        setReports(data.reports || []);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load community feed');
        setLoading(false);
      });
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleVote = async (reportId: string, vote: 'UPVOTE' | 'DOWNVOTE') => {
    try {
      await voteCommunityReport(reportId, vote);
      loadReports();
    } catch (err: any) {
      alert(err.message || 'Failed to submit vote');
    }
  };

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    setFormSuccess(null);

    try {
      await submitCommunityReport({
        url: url.trim(),
        category,
        description: description.trim(),
        submitterEmail: submitterEmail.trim() || undefined,
      });

      setFormSuccess('Threat report submitted for community verification.');
      setUrl('');
      setDescription('');
      loadReports();
      setTimeout(() => setShowForm(false), 2000);
    } catch (err: any) {
      setFormError(err.message || 'Failed to submit report');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 py-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <Users className="w-6 h-6 text-electric-400" />
            Community Threat Intelligence
          </h1>
          <p className="mt-1 text-xs font-mono text-slate-400">
            Collaborative threat reporting and crowdsourced peer consensus.
          </p>
        </div>

        <button
          onClick={() => setShowForm(!showForm)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-xs font-mono transition-all shadow-glow"
        >
          <Plus className="w-4 h-4" />
          {showForm ? 'Close Form' : 'Report Suspicious Link'}
        </button>
      </div>

      {/* Submission Form */}
      {showForm && (
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl transition-all">
          <h3 className="text-sm font-bold text-white mb-4">Submit Community Threat Report</h3>
          <form onSubmit={handleCreateReport} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Suspicious URL</label>
                <input
                  type="text"
                  placeholder="https://malicious-login-target.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-white focus:outline-none focus:border-electric-400"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Threat Category</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value as ThreatCategory)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-white focus:outline-none focus:border-electric-400"
                >
                  {Object.values(ThreatCategoryEnum).map((cat) => (
                    <option key={cat} value={cat}>
                      {cat}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Forensic Context & Description (min 10 characters)
              </label>
              <textarea
                rows={3}
                placeholder="Explain the deceptive behavior, credential harvesting mechanism, or spoofed brand..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-white focus:outline-none focus:border-electric-400"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Your Email (Optional, for attribution)
              </label>
              <input
                type="email"
                placeholder="analyst@domain.com"
                value={submitterEmail}
                onChange={(e) => setSubmitterEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-white focus:outline-none focus:border-electric-400"
              />
            </div>

            {formError && (
              <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs font-mono text-red-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            {formSuccess && (
              <div className="p-3 bg-emerald-950/40 border border-emerald-800 rounded-lg text-xs font-mono text-emerald-300 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                {formSuccess}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2.5 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-xs font-mono transition-colors disabled:opacity-50"
            >
              {submitting ? 'Submitting...' : 'Submit Report'}
            </button>
          </form>
        </div>
      )}

      {/* Reports Feed */}
      {loading ? (
        <LoadingState message="Loading Crowdsourced Reports..." />
      ) : error ? (
        <ErrorState message={error} onRetry={loadReports} />
      ) : reports.length === 0 ? (
        <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-slate-500 font-mono text-xs">
          No community reports submitted yet. Be the first to flag a suspicious threat!
        </div>
      ) : (
        <div className="space-y-4">
          {reports.map((report) => (
            <div
              key={report._id}
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
            >
              <div className="space-y-1.5 flex-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold bg-amber-950/70 border border-amber-500/40 text-amber-300">
                    {report.category}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500 bg-slate-800/80 px-2 py-0.5 rounded">
                    Status: {report.status}
                  </span>
                  {report.reportCount > 1 && (
                    <span className="text-[11px] font-mono text-electric-400">
                      {report.reportCount} reports
                    </span>
                  )}
                </div>

                <h3 className="font-mono text-sm font-bold text-white break-all">
                  {report.submittedUrl}
                </h3>
                <p className="text-xs text-slate-300 font-mono">{report.description}</p>
                <div className="text-[10px] font-mono text-slate-500 flex items-center gap-2 pt-1">
                  <span>Domain: {report.normalizedDomain}</span>
                  <span>•</span>
                  <span>{new Date(report.createdAt).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Voting Controls */}
              <div className="flex items-center gap-2 border-t sm:border-t-0 sm:border-l border-slate-800 pt-3 sm:pt-0 sm:pl-4">
                <button
                  onClick={() => handleVote(report._id, 'UPVOTE')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                    report.userVote === 'UPVOTE'
                      ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                  }`}
                  title="Verify threat as accurate"
                >
                  <ThumbsUp className="w-3.5 h-3.5" />
                  <span>{report.upvotes || 0}</span>
                </button>

                <button
                  onClick={() => handleVote(report._id, 'DOWNVOTE')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                    report.userVote === 'DOWNVOTE'
                      ? 'bg-red-950/80 border-red-500 text-red-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                  }`}
                  title="Flag report as inaccurate / false positive"
                >
                  <ThumbsDown className="w-3.5 h-3.5" />
                  <span>{report.downvotes || 0}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
