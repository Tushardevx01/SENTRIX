// ==========================================
// Enums & Domain Status Types
// ==========================================

export const ScanStatusEnum = {
  QUEUED: 'QUEUED',
  PROCESSING: 'PROCESSING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  // Backward compatibility aliases
  PENDING: 'PENDING',
  IN_PROGRESS: 'IN_PROGRESS',
} as const;
export type ScanStatus = (typeof ScanStatusEnum)[keyof typeof ScanStatusEnum];

export const VerdictEnum = {
  BENIGN: 'BENIGN',
  SUSPICIOUS: 'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
  INCONCLUSIVE: 'INCONCLUSIVE',
} as const;
export type Verdict = (typeof VerdictEnum)[keyof typeof VerdictEnum];

export const AnalysisStatusEnum = {
  COMPLETE: 'COMPLETE',
  PARTIAL: 'PARTIAL',
  FAILED: 'FAILED',
} as const;
export type AnalysisStatus = (typeof AnalysisStatusEnum)[keyof typeof AnalysisStatusEnum];

export const FindingCategoryEnum = {
  URL_ANOMALY: 'URL_ANOMALY',
  DOMAIN_REPUTATION: 'DOMAIN_REPUTATION',
  TLS_SECURITY: 'TLS_SECURITY',
  WEB_SECURITY: 'WEB_SECURITY',
  PHISHING_INDICATOR: 'PHISHING_INDICATOR',
  BLACKLIST: 'BLACKLIST',
} as const;
export type FindingCategory = (typeof FindingCategoryEnum)[keyof typeof FindingCategoryEnum];

export const FindingSeverityEnum = {
  INFO: 'INFO',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
} as const;
export type FindingSeverity = (typeof FindingSeverityEnum)[keyof typeof FindingSeverityEnum];

export const ThreatCategoryEnum = {
  PHISHING: 'PHISHING',
  MALWARE: 'MALWARE',
  SCAM: 'SCAM',
  IMPERSONATION: 'IMPERSONATION',
  DEFACEMENT: 'DEFACEMENT',
  SUSPICIOUS: 'SUSPICIOUS',
} as const;
export type ThreatCategory = (typeof ThreatCategoryEnum)[keyof typeof ThreatCategoryEnum];

export const ThreatReportStatusEnum = {
  SUBMITTED: 'SUBMITTED',
  UNDER_REVIEW: 'UNDER_REVIEW',
  CONFIRMED: 'CONFIRMED',
  DISMISSED: 'DISMISSED',
} as const;
export type ThreatReportStatus = (typeof ThreatReportStatusEnum)[keyof typeof ThreatReportStatusEnum];

export const VoteTypeEnum = {
  UPVOTE: 'UPVOTE',
  DOWNVOTE: 'DOWNVOTE',
} as const;
export type VoteType = (typeof VoteTypeEnum)[keyof typeof VoteTypeEnum];

export const RiskThresholds = {
  BENIGN_MAX: 25,
  SUSPICIOUS_MAX: 69,
  MALICIOUS_MIN: 70,
} as const;

// ==========================================
// Domain Entity Interfaces
// ==========================================

export interface AnalyzerStatusMap {
  urlAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | 'PENDING';
  domainAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | 'PENDING';
  tlsAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | 'PENDING';
  webSecurityAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | 'PENDING';
  reputationAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | 'PENDING';
  [key: string]: string;
}

export interface IScan {
  _id: string;
  submittedUrl: string;
  normalizedDomain: string;
  urlHash?: string;
  status: ScanStatus;
  riskScore: number;
  verdict: Verdict;
  confidence: number;
  analysisStatus?: AnalysisStatus;
  analysisComplete?: boolean;
  analyzerStatuses: AnalyzerStatusMap;
  retryCount?: number;
  workerId?: string;
  claimedAt?: string;
  leaseToken?: string;
  publishedLeaseToken?: string;
  errorMessage?: string;
  summary?: any;
  createdAt: string;
  completedAt?: string;
}

export interface IFinding {
  _id: string;
  scanId: string;
  leaseToken?: string;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  confidence: number;
  createdAt?: string;
}

export interface ICertificate {
  _id: string;
  scanId: string;
  leaseToken?: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  fingerprint: string;
  hostnameMatched: boolean;
  keyAlgorithm?: string;
  keySize?: number;
  signatureAlgorithm?: string;
  hasSCTs?: boolean;
  validityDays?: number;
  rawDetails?: Record<string, unknown>;
  createdAt?: string;
}

export const UserRoleEnum = {
  USER: 'user',
  ANALYST: 'analyst',
  ADMIN: 'admin',
} as const;
export type UserRole = (typeof UserRoleEnum)[keyof typeof UserRoleEnum];

export interface IUser {
  _id: string;
  email: string;
  role: UserRole;
  createdAt: string;
  updatedAt?: string;
}

export interface AuthResponse {
  token: string;
  user: IUser;
}

export interface IThreatReport {
  _id: string;
  submittedUrl: string;
  normalizedDomain: string;
  urlHash: string;
  category: ThreatCategory;
  description: string;
  status: ThreatReportStatus;
  reportCount: number;
  upvotes?: number;
  downvotes?: number;
  userVote?: VoteType | null;
  createdAt: string;
}

export interface DashboardStats {
  totalScans: number;
  maliciousCount: number;
  suspiciousCount: number;
  benignCount: number;
  averageRiskScore: number;
  threatsReported: number;
  recentScans: Array<{
    _id: string;
    submittedUrl: string;
    normalizedDomain: string;
    riskScore: number;
    verdict: Verdict;
    createdAt: string;
  }>;
}

export interface ScanReportDetail {
  scan: IScan;
  findings: IFinding[];
  certificate: ICertificate | null;
  summary: {
    threatTypes: string[];
    riskFactors: string[];
    redirectChain?: string[];
    responseTimeMs?: number;
    inconclusiveReasons?: string[];
    isTruncated?: boolean;
  };
}
