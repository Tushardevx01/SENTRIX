import { z } from 'zod';

// ==========================================
// Enums & Constants
// ==========================================

export const ScanStatusEnum = {
  PENDING: 'PENDING',
  IN_PROGRESS: 'IN_PROGRESS',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
} as const;
export type ScanStatus = (typeof ScanStatusEnum)[keyof typeof ScanStatusEnum];

export const VerdictEnum = {
  BENIGN: 'BENIGN',
  SUSPICIOUS: 'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
} as const;
export type Verdict = (typeof VerdictEnum)[keyof typeof VerdictEnum];

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
// Zod Schemas for Validation
// ==========================================

export const UrlScanRequestSchema = z.object({
  url: z
    .string()
    .trim()
    .min(3, 'URL is too short')
    .max(2048, 'URL exceeds maximum length')
    .refine(
      (val) => {
        try {
          // Allow URLs without scheme by prepending http:// for check
          const toCheck = val.match(/^https?:\/\//i) ? val : `http://${val}`;
          const parsed = new URL(toCheck);
          return (
            (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
            Boolean(parsed.hostname) &&
            parsed.hostname.includes('.')
          );
        } catch {
          return false;
        }
      },
      { message: 'Invalid URL or hostname format. Provide a valid domain or http/https URL.' }
    ),
  deepScan: z.boolean().optional().default(false),
});
export type UrlScanRequest = z.infer<typeof UrlScanRequestSchema>;

export const ThreatReportCreateSchema = z.object({
  url: z.string().trim().min(3).max(2048),
  category: z.nativeEnum(ThreatCategoryEnum),
  description: z.string().trim().min(10, 'Description must be at least 10 characters').max(2000),
  submitterEmail: z.string().email().optional(),
});
export type ThreatReportCreate = z.infer<typeof ThreatReportCreateSchema>;

export const ThreatVoteCreateSchema = z.object({
  vote: z.nativeEnum(VoteTypeEnum),
  sessionIdentifier: z.string().trim().min(4).max(128).optional(),
});
export type ThreatVoteCreate = z.infer<typeof ThreatVoteCreateSchema>;

// ==========================================
// Scanner Service Contract Schemas
// ==========================================

export const ScannerAnalysisRequestSchema = z.object({
  url: z.string().min(1),
  scanId: z.string().min(1),
  normalizedDomain: z.string().min(1),
  deepScan: z.boolean().optional().default(false),
});
export type ScannerAnalysisRequest = z.infer<typeof ScannerAnalysisRequestSchema>;

export interface RawFinding {
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  confidence: number;
}

export interface CertificateInfo {
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  fingerprint: string;
  hostnameMatched: boolean;
  rawDetails?: Record<string, unknown>;
}

export interface AnalyzerStatusMap {
  urlAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  domainAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  tlsAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  webSecurityAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  reputationAnalyzer: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  [key: string]: string;
}

export interface ScannerAnalysisResponse {
  scanId: string;
  targetUrl: string;
  normalizedDomain: string;
  ipAddress?: string;
  riskScore: number;
  verdict: Verdict;
  confidence: number;
  analyzerStatuses: AnalyzerStatusMap;
  findings: RawFinding[];
  certificate?: CertificateInfo | null;
  summary: {
    threatTypes: string[];
    riskFactors: string[];
    mitreTactics?: string[];
    redirectChain?: string[];
    responseTimeMs?: number;
  };
}

// ==========================================
// Application Data Interfaces
// ==========================================

export interface IScan {
  _id: string;
  submittedUrl: string;
  normalizedDomain: string;
  status: ScanStatus;
  riskScore: number;
  verdict: Verdict;
  confidence: number;
  analyzerStatuses: AnalyzerStatusMap;
  createdAt: string;
  completedAt?: string;
}

export interface IFinding {
  _id: string;
  scanId: string;
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
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  fingerprint: string;
  hostnameMatched: boolean;
  createdAt?: string;
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
  };
}

// ==========================================
// Helper Utility Functions
// ==========================================

/**
 * Normalizes input URL into standard format:
 * - Adds scheme if missing
 * - Extracts and normalizes hostname (lowercase, strips default ports, trailing slashes)
 */
export function normalizeUrl(rawUrl: string): { normalizedUrl: string; normalizedDomain: string } {
  let target = rawUrl.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = `https://${target}`;
  }

  const parsed = new URL(target);
  const normalizedDomain = parsed.hostname.toLowerCase();
  
  // Clean standard ports
  if (
    (parsed.protocol === 'https:' && parsed.port === '443') ||
    (parsed.protocol === 'http:' && parsed.port === '80')
  ) {
    parsed.port = '';
  }

  return {
    normalizedUrl: parsed.toString(),
    normalizedDomain,
  };
}

/**
 * Derives verdict from risk score
 */
export function getVerdictFromScore(score: number): Verdict {
  if (score >= RiskThresholds.MALICIOUS_MIN) return VerdictEnum.MALICIOUS;
  if (score > RiskThresholds.BENIGN_MAX) return VerdictEnum.SUSPICIOUS;
  return VerdictEnum.BENIGN;
}
