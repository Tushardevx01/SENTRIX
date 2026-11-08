'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Users,
  ThumbsUp,
  ThumbsDown,
  Plus,
  AlertCircle,
  CheckCircle2,
  Clock,
  Send,
  X,
  ExternalLink,
  Terminal,
} from 'lucide-react';
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
    <div className="space-y-8 py-2 max-w-5xl mx-auto font-mono text-xs">
      {/* Top Header & Normal dark gray button with white text */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <Users className="w-3.5 h-3.5" />
            <span>[ COMMUNITY // PEER CONSENSUS ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Community Threat Feed
          </h1>
          <p className="text-xs text-neutral-500 font-mono">
            Crowdsourced threat submissions, authenticated voting, and reputation scoring.
          </p>
        </div>

        {/* Normal dark gray button with white button text */}
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-industrial py-2.5 px-4 rounded-full text-xs font-semibold cursor-pointer"
        >
          <Plus className="w-4 h-4 text-white" />
          <span>Report Threat Endpoint</span>
        </button>
      </div>

      {/* Submission Form Modal/Card */}
      {showForm && (
        <div className="p-5 sm:p-6 rounded-xl border border-neutral-300 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-card space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
            <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              // SUBMIT CROWDSOURCED THREAT REPORT
            </span>
            <button
              onClick={() => setShowForm(false)}
              className="p-1 rounded text-neutral-400 hover:text-black dark:hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {formSuccess && (
            <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 text-emerald-800 dark:text-emerald-300">
              {formSuccess}
            </div>
          )}

          {formError && (
            <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-red-800 dark:text-red-300">
              {formError}
            </div>
          )}

          <form onSubmit={handleCreateReport} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
                  Target Destination URL
                </label>
                <input
                  type="text"
                  required
                  placeholder="https://paypal-update-login.xyz/auth"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white focus:outline-none focus:border-black dark:focus:border-white"
                />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
                  Observed Category
                </label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value as ThreatCategory)}
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white focus:outline-none focus:border-black dark:focus:border-white"
                >
                  <option value={ThreatCategoryEnum.PHISHING}>Credential Phishing</option>
                  <option value={ThreatCategoryEnum.MALWARE}>Malware Distribution</option>
                  <option value={ThreatCategoryEnum.SCAM}>Scam / Financial Fraud</option>
                  <option value={ThreatCategoryEnum.IMPERSONATION}>Brand Impersonation</option>
                  <option value={ThreatCategoryEnum.DEFACEMENT}>Website Defacement</option>
                  <option value={ThreatCategoryEnum.SUSPICIOUS}>Suspicious Infrastructure</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
                Forensic Incident Description
              </label>
              <textarea
                rows={3}
                required
                placeholder="Explain observed threats, credential harvesting inputs, or deceptive brand spoofing..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full p-3 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white focus:outline-none focus:border-black dark:focus:border-white"
              />
            </div>

            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="px-4 py-2 rounded-lg border border-neutral-300 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300 hover:text-black dark:hover:text-white cursor-pointer"
              >
                Cancel
              </button>
              {/* Normal dark gray button with white button text */}
              <button
                type="submit"
                disabled={submitting}
                className="btn-industrial py-2 px-5 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                {submitting ? 'Submitting Report...' : 'Publish to Feed'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Reports Feed */}
      {loading ? (
        <LoadingState message="Loading Peer Threat Reports..." />
      ) : error ? (
        <ErrorState title="Community Feed Error" message={error} onRetry={() => loadReports()} />
      ) : reports.length === 0 ? (
        <div className="p-12 text-center border border-neutral-200 dark:border-[#27272a] rounded-xl bg-white dark:bg-[#0c0c0e] text-neutral-400 space-y-2">
          <p>No community threat reports submitted yet.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {reports.map((rep) => (
            <div
              key={rep._id}
              className="p-5 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4"
            >
              <div className="space-y-1.5 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase font-pixel px-2 py-0.5 rounded bg-neutral-100 dark:bg-[#18181b] text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-[#27272a]">
                    {rep.category}
                  </span>
                  <span className="text-neutral-400 text-[10px]">
                    {new Date(rep.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-black dark:text-white truncate max-w-lg">
                  {rep.submittedUrl}
                </h3>
                <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
                  {rep.description}
                </p>
              </div>

              {/* Voting & Actions */}
              <div className="flex items-center gap-3 shrink-0">
                <div className="flex items-center gap-1 bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] p-1 rounded-full">
                  <button
                    type="button"
                    onClick={() => handleVote(rep._id, 'UPVOTE')}
                    className="p-1.5 rounded-full hover:bg-neutral-200 dark:hover:bg-[#1f1f23] text-emerald-600 dark:text-emerald-400 transition-colors cursor-pointer"
                    title="Confirm threat"
                  >
                    <ThumbsUp className="w-3.5 h-3.5" />
                  </button>
                  <span className="px-1 font-bold text-xs">{(rep.upvotes || 0) - (rep.downvotes || 0)}</span>
                  <button
                    type="button"
                    onClick={() => handleVote(rep._id, 'DOWNVOTE')}
                    className="p-1.5 rounded-full hover:bg-neutral-200 dark:hover:bg-[#1f1f23] text-red-600 dark:text-red-400 transition-colors cursor-pointer"
                    title="Dismiss threat"
                  >
                    <ThumbsDown className="w-3.5 h-3.5" />
                  </button>
                </div>

                <Link
                  href={`/scanner?target=${encodeURIComponent(rep.submittedUrl)}`}
                  className="btn-industrial text-[11px] py-1.5 px-3 rounded-full"
                >
                  Verify URL
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
