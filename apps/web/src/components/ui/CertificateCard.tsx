import React from 'react';
import { Lock, CheckCircle2, XCircle, Calendar, Hash, Server } from 'lucide-react';
import { type ICertificate } from '@sentrix/shared';

interface CertificateCardProps {
  certificate: ICertificate | null;
}

export const CertificateCard: React.FC<CertificateCardProps> = ({ certificate }) => {
  if (!certificate) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-6 text-center text-slate-400">
        <Lock className="w-8 h-8 mx-auto mb-2 text-slate-600" />
        <p className="text-sm">No SSL/TLS certificate was collected for this target.</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Lock className="w-5 h-5 text-electric-400" />
          <h3 className="font-semibold text-slate-100 text-sm">TLS Certificate Information</h3>
        </div>
        <div className="flex items-center gap-1.5 text-xs font-mono">
          {certificate.hostnameMatched ? (
            <span className="flex items-center gap-1 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> Hostname Validated
            </span>
          ) : (
            <span className="flex items-center gap-1 text-red-400">
              <XCircle className="w-3.5 h-3.5" /> Hostname Mismatch
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        <div>
          <span className="text-slate-500 block mb-1">Issuer Authority</span>
          <span className="text-slate-200 bg-slate-950 px-2 py-1 rounded block truncate" title={certificate.issuer}>
            {certificate.issuer}
          </span>
        </div>

        <div>
          <span className="text-slate-500 block mb-1">Subject / Domain</span>
          <span className="text-slate-200 bg-slate-950 px-2 py-1 rounded block truncate" title={certificate.subject}>
            {certificate.subject}
          </span>
        </div>

        <div>
          <span className="text-slate-500 block mb-1">Validity Period</span>
          <div className="flex items-center gap-2 text-slate-300 bg-slate-950 px-2 py-1 rounded">
            <Calendar className="w-3.5 h-3.5 text-slate-500" />
            <span>{new Date(certificate.validFrom).toLocaleDateString()} – {new Date(certificate.validUntil).toLocaleDateString()}</span>
          </div>
        </div>

        <div>
          <span className="text-slate-500 block mb-1">SHA-256 Fingerprint</span>
          <div className="flex items-center gap-2 text-electric-300 bg-slate-950 px-2 py-1 rounded font-mono truncate" title={certificate.fingerprint}>
            <Hash className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <span className="truncate">{certificate.fingerprint}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
