'use client';

import React, { useEffect, useState } from 'react';
import {
  Users,
  ThumbsUp,
  ThumbsDown,
  Plus,
  AlertCircle,
  CheckCircle2,
  Globe,
  Radio,
  Clock,
  Send,
  X,
  ExternalLink,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
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

      setFormSuccess('Threat report submitted for community peer verification.');
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
    <div className="space-y-8 py-2 max-w-5xl mx-auto">
      {/* Top Header & Report Button */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
            <Users className="w-3.5 h-3.5" />
            <span>Crowdsourced Threat Verification</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
            COMMUNITY INTELLIGENCE FEED
          </h1>
          <p className="text-xs text-theme-muted font-mono">
            Peer-reviewed suspicious links, phishing campaign flags, and consensus voting.
          </p>
        </div>

        <button
          onClick={() => setShowForm(!showForm)}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 shadow-sm shrink-0"
        >
          {showForm ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          <span>{showForm ? 'Close Drawer' : 'Report Suspicious Link'}</span>
        </button>
      </div>

      {/* Community KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            Community Reports
          </span>
          <span className="text-2xl font-black font-mono text-theme-text block">
            {reports.length}
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Crowdsourced submissions</span>
        </div>
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            Consensus Verification
          </span>
          <span className="text-2xl font-black font-mono text-theme-success block flex items-center gap-1.5">
            <CheckCircle2 className="w-5 h-5" /> 1-IP 1-Vote
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Anti-fraud IP hashing active</span>
        </div>
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            Voting Rate Limit
          </span>
          <span className="text-2xl font-black font-mono text-theme-accent block">
            20 / min
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Strict HTTP 429 protection</span>
        </div>
      </div>

      {/* Submission Form Drawer */}
      <AnimatePresence>
        {showForm && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-card space-y-4">
              <h3 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
                <Send className="w-4 h-4 text-theme-accent" />
                <span>SUBMIT NEW THREAT REPORT FOR COMMUNITY REVIEW</span>
              </h3>

              <form onSubmit={handleCreateReport} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-mono font-semibold text-theme-text mb-1">
                      Suspicious Destination URL *
                    </label>
                    <input
                      type="text"
                      placeholder="https://malicious-portal-verify.com/login"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-xs font-mono text-theme-text placeholder:text-theme-muted focus:outline-none focus:border-theme-accent"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-mono font-semibold text-theme-text mb-1">
                      Threat Classification *
                    </label>
                    <select
                      value={category}
                      onChange={(e) => setCategory(e.target.value as ThreatCategory)}
                      className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-xs font-mono text-theme-text focus:outline-none focus:border-theme-accent"
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
                  <label className="block text-xs font-mono font-semibold text-theme-text mb-1">
                    Forensic Context & Observed Deception *
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Describe brand logos spoofed, fake login forms, or observed exfiltration endpoints..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-xs font-mono text-theme-text placeholder:text-theme-muted focus:outline-none focus:border-theme-accent"
                    required
                    minLength={10}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-mono font-semibold text-theme-text mb-1">
                      Reporter Identity (Optional email)
                    </label>
                    <input
                      type="email"
                      placeholder="analyst@soc.org"
                      value={submitterEmail}
                      onChange={(e) => setSubmitterEmail(e.target.value)}
                      className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-xs font-mono text-theme-text placeholder:text-theme-muted focus:outline-none focus:border-theme-accent"
                    />
                  </div>
                  <div className="flex items-end">
                    <button
                      type="submit"
                      disabled={submitting}
                      className="w-full py-2.5 px-4 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 disabled:opacity-50"
                    >
                      {submitting ? 'Submitting Report...' : 'Publish to Feed'}
                    </button>
                  </div>
                </div>

                {formSuccess && (
                  <div className="p-3 bg-theme-success/10 border border-theme-success/30 rounded-lg text-xs font-mono text-theme-success flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>{formSuccess}</span>
                  </div>
                )}

                {formError && (
                  <div className="p-3 bg-theme-danger/10 border border-theme-danger/30 rounded-lg text-xs font-mono text-theme-danger flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{formError}</span>
                  </div>
                )}
              </form>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Community Feed List */}
      {loading ? (
        <LoadingState message="Fetching Community Threat Feed..." />
      ) : error ? (
        <ErrorState message={error} onRetry={loadReports} />
      ) : reports.length === 0 ? (
        <div className="p-12 text-center rounded-xl border border-dashed border-theme-border text-xs font-mono text-theme-muted">
          No community reports submitted yet. Be the first to flag a suspicious destination.
        </div>
      ) : (
        <div className="space-y-4">
          {reports.map((report) => (
            <div
              key={report._id}
              className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
            >
              <div className="space-y-2 flex-1">
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                  <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-bold uppercase border border-amber-500/20 text-[10px]">
                    {report.category}
                  </span>
                  <span className="text-theme-muted text-[11px]">
                    Status: <strong className="text-theme-text">{report.status}</strong>
                  </span>
                  <span className="text-theme-muted text-[11px] flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(report.createdAt).toLocaleDateString()}
                  </span>
                </div>

                <h3 className="text-sm font-bold font-mono text-theme-text break-all">
                  {report.submittedUrl}
                </h3>

                <p className="text-xs font-mono text-theme-muted leading-relaxed">
                  {report.description}
                </p>
              </div>

              {/* Upvote / Downvote Controls */}
              <div className="flex items-center gap-2 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-theme-borderSubtle w-full sm:w-auto justify-end">
                <button
                  onClick={() => handleVote(report._id, 'UPVOTE')}
                  type="button"
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                    report.userVote === 'UPVOTE'
                      ? 'border-theme-success bg-theme-success/10 text-theme-success font-bold'
                      : 'border-theme-border bg-theme-elevated text-theme-muted hover:text-theme-text'
                  }`}
                  title="Confirm this threat"
                >
                  <ThumbsUp className="w-3.5 h-3.5" />
                  <span>{report.upvotes || 0}</span>
                </button>

                <button
                  onClick={() => handleVote(report._id, 'DOWNVOTE')}
                  type="button"
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                    report.userVote === 'DOWNVOTE'
                      ? 'border-theme-danger bg-theme-danger/10 text-theme-danger font-bold'
                      : 'border-theme-border bg-theme-elevated text-theme-muted hover:text-theme-text'
                  }`}
                  title="Dispute this threat"
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
