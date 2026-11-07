import { z } from 'zod';
import {
  ThreatCategoryEnum,
  VoteTypeEnum,
  type FindingCategory,
  type FindingSeverity,
  type Verdict,
  type AnalyzerStatusMap,
  type AnalysisStatus,
} from '../types/index.js';

// ==========================================
// Zod Request & Input Validation Contracts
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
// Scanner Micro-Contract Interfaces
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

export interface ScannerAnalysisResponse {
  scanId: string;
  targetUrl: string;
  normalizedDomain: string;
  ipAddress?: string;
  riskScore: number;
  verdict: Verdict;
  confidence: number;
  analysisStatus?: AnalysisStatus;
  analysisComplete?: boolean;
  analyzerStatuses: AnalyzerStatusMap;
  findings: RawFinding[];
  certificate?: CertificateInfo | null;
  summary: {
    threatTypes: string[];
    riskFactors: string[];
    mitreTactics?: string[];
    redirectChain?: string[];
    responseTimeMs?: number;
    inconclusiveReasons?: string[];
    isTruncated?: boolean;
  };
}
