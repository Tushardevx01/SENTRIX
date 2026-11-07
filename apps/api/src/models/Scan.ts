import mongoose, { Schema, Document } from 'mongoose';
import {
  ScanStatusEnum,
  VerdictEnum,
  AnalysisStatusEnum,
  type ScanStatus,
  type Verdict,
  type AnalysisStatus,
  type AnalyzerStatusMap,
} from '@sentrix/shared';

export interface IScanDocument extends Document {
  submittedUrl: string;
  normalizedDomain: string;
  urlHash?: string;
  status: ScanStatus;
  riskScore: number;
  verdict: Verdict;
  confidence: number;
  analysisStatus: AnalysisStatus;
  analysisComplete: boolean;
  analyzerStatuses: AnalyzerStatusMap;
  summary?: {
    threatTypes: string[];
    riskFactors: string[];
    mitreTactics?: string[];
    redirectChain?: string[];
    responseTimeMs?: number;
    inconclusiveReasons?: string[];
    isTruncated?: boolean;
  };
  retryCount: number;
  workerId?: string;
  claimedAt?: Date;
  leaseToken?: string;
  publishedLeaseToken?: string;
  lastError?: string;
  timeoutSeconds?: number;
  errorMessage?: string;
  completedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ScanSchema = new Schema<IScanDocument>(
  {
    submittedUrl: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    normalizedDomain: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    urlHash: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: Object.values(ScanStatusEnum),
      default: ScanStatusEnum.QUEUED,
      index: true,
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    verdict: {
      type: String,
      enum: Object.values(VerdictEnum),
      default: VerdictEnum.BENIGN,
      index: true,
    },
    confidence: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    analysisStatus: {
      type: String,
      enum: Object.values(AnalysisStatusEnum),
      default: AnalysisStatusEnum.COMPLETE,
      index: true,
    },
    analysisComplete: {
      type: Boolean,
      default: true,
    },
    analyzerStatuses: {
      type: Map,
      of: String,
      default: () => ({
        urlAnalyzer: 'PENDING',
        domainAnalyzer: 'PENDING',
        tlsAnalyzer: 'PENDING',
        webSecurityAnalyzer: 'PENDING',
        reputationAnalyzer: 'PENDING',
      }),
    },
    summary: {
      threatTypes: { type: [String], default: [] },
      riskFactors: { type: [String], default: [] },
      mitreTactics: { type: [String], default: [] },
      redirectChain: { type: [String], default: [] },
      responseTimeMs: { type: Number },
      inconclusiveReasons: { type: [String], default: [] },
      isTruncated: { type: Boolean, default: false },
    },
    errorMessage: {
      type: String,
    },
    retryCount: {
      type: Number,
      default: 0,
      min: 0,
      index: true,
    },
    workerId: {
      type: String,
      index: true,
    },
    claimedAt: {
      type: Date,
      index: true,
    },
    leaseToken: {
      type: String,
      index: true,
    },
    publishedLeaseToken: {
      type: String,
      index: true,
    },
    lastError: {
      type: String,
    },
    timeoutSeconds: {
      type: Number,
      default: 60,
    },
    completedAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

ScanSchema.index({ normalizedDomain: 1, createdAt: -1 });
ScanSchema.index({ createdAt: -1 });
ScanSchema.index({ status: 1, createdAt: 1 }); // FIFO queue query index
ScanSchema.index({ status: 1, claimedAt: 1 }); // Stale processing reaper index
ScanSchema.index({ urlHash: 1, status: 1 }); // Duplicate active scan lookup
ScanSchema.index(
  { urlHash: 1 },
  {
    unique: true,
    partialFilterExpression: {
      status: { $in: ['QUEUED', 'PROCESSING'] },
    },
  }
); // Prevent concurrent duplicate active scans in QUEUED/PROCESSING state

export const ScanModel = mongoose.models.Scan || mongoose.model<IScanDocument>('Scan', ScanSchema);
