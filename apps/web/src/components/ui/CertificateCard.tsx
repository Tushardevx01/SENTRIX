import React from 'react';
import { Lock, CheckCircle2, XCircle, Calendar, Hash, Shield } from 'lucide-react';
import { type ICertificate } from '@sentrix/shared';

interface CertificateCardProps {
  certificate: ICertificate | null;
}

export const CertificateCard: React.FC<CertificateCardProps> = ({ certificate }) => {
  if (!certificate) {
    return (
      <div className="bg-theme-card border border-theme-border rounded-xl p-6 text-center text-theme-muted">
        <Lock className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-xs font-mono">No SSL/TLS certificate was collected for this target.</p>
      </div>
    );
  }

  const isExpired = new Date(certificate.validUntil) < new Date();

  return (
    <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-xs">
      <div className="flex items-center justify-between border-b border-theme-borderSubtle pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-theme-accent" />
          <h3 className="font-bold text-theme-text text-sm font-mono">TLS Certificate Information</h3>
        </div>
        <div className="flex items-center gap-1.5 text-xs font-mono">
          {certificate.hostnameMatched ? (
            <span className="flex items-center gap-1 text-theme-success font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" /> Hostname Matched
            </span>
          ) : (
            <span className="flex items-center gap-1 text-theme-danger font-semibold">
              <XCircle className="w-3.5 h-3.5" /> Hostname Mismatch
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        <div>
          <span className="text-theme-muted block mb-1">Issuer Authority</span>
          <span
            className="text-theme-text bg-theme-elevated px-2.5 py-1.5 rounded-lg border border-theme-borderSubtle block truncate"
            title={certificate.issuer}
          >
            {certificate.issuer}
          </span>
        </div>

        <div>
          <span className="text-theme-muted block mb-1">Subject / Domain</span>
          <span
            className="text-theme-text bg-theme-elevated px-2.5 py-1.5 rounded-lg border border-theme-borderSubtle block truncate"
            title={certificate.subject}
          >
            {certificate.subject}
          </span>
        </div>

        <div>
          <span className="text-theme-muted block mb-1">Validity Period</span>
          <div className="flex items-center gap-2 text-theme-text bg-theme-elevated px-2.5 py-1.5 rounded-lg border border-theme-borderSubtle">
            <Calendar className="w-3.5 h-3.5 text-theme-muted" />
            <span>
              {new Date(certificate.validFrom).toLocaleDateString()} –{' '}
              {new Date(certificate.validUntil).toLocaleDateString()}
            </span>
            {isExpired && (
              <span className="text-[10px] text-theme-danger font-bold uppercase ml-auto">
                Expired
              </span>
            )}
          </div>
        </div>

        <div>
          <span className="text-theme-muted block mb-1">SHA-256 Fingerprint</span>
          <span
            className="text-theme-text bg-theme-elevated px-2.5 py-1.5 rounded-lg border border-theme-borderSubtle block truncate font-mono text-[11px]"
            title={certificate.fingerprint}
          >
            {certificate.fingerprint || 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );
};
