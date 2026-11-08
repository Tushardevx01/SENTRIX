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

export const UserRegisterSchema = z
  .object({
    email: z.string().trim().email('Invalid email address format').max(255),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password must not exceed 128 characters'),
  })
  .strip();
export type UserRegister = z.infer<typeof UserRegisterSchema>;

export const UserRoleUpdateSchema = z.object({
  role: z.enum(['user', 'analyst', 'admin'], {
    errorMap: () => ({ message: "Role must be 'user', 'analyst', or 'admin'" }),
  }),
});
export type UserRoleUpdate = z.infer<typeof UserRoleUpdateSchema>;

export const UserLoginSchema = z
  .object({
    email: z.string().trim().email('Invalid email address format'),
    password: z
      .string()
      .min(1, 'Password is required')
      .max(128, 'Password must not exceed 128 characters'),
  })
  .strip();
export type UserLogin = z.infer<typeof UserLoginSchema>;

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

// ==========================================
// Message Analysis Request Contract
// ==========================================

export const MessageAnalyzeRequestSchema = z.object({
  messageText: z
    .string()
    .trim()
    .min(5, 'Message text must be at least 5 characters')
    .max(50000, 'Message text exceeds maximum length of 50,000 characters'),
  senderInfo: z.string().trim().max(256).optional(),
  channel: z.enum(['SMS', 'WHATSAPP', 'EMAIL', 'TELEGRAM', 'SOCIAL_MEDIA', 'OTHER']).optional().default('OTHER'),
});
export type MessageAnalyzeRequest = z.infer<typeof MessageAnalyzeRequestSchema>;

// ==========================================
// Blockchain Threat Registry Contracts
// ==========================================

export const BlockchainRegisterRequestSchema = z.object({
  reportId: z.string().trim().min(1, 'Report ID is required'),
  reportType: z.enum(['SCAN', 'MESSAGE', 'THREAT_REPORT']).default('SCAN'),
});
export type BlockchainRegisterRequest = z.infer<typeof BlockchainRegisterRequestSchema>;

export const BlockchainVerifyRequestSchema = z.object({
  reportId: z.string().trim().min(1, 'Report ID is required'),
  reportType: z.enum(['SCAN', 'MESSAGE', 'THREAT_REPORT']).optional().default('SCAN'),
  reportHash: z.string().trim().regex(/^0x[a-fA-F0-9]{64}$/, 'Report hash must be a 32-byte hex string').optional(),
});
export type BlockchainVerifyRequest = z.infer<typeof BlockchainVerifyRequestSchema>;

// ==========================================
// AI Explanation Request Contract
// ==========================================

export const AIExplanationRequestSchema = z.object({
  contextType: z.enum(['SCAN', 'MESSAGE', 'CERTIFICATE', 'CORRELATION']),
  target: z.string().trim().min(1),
  findingsSummary: z.array(z.string()).optional(),
  riskScore: z.number().min(0).max(100).optional(),
  verdict: z.string().optional(),
  evidence: z.record(z.unknown()).optional(),
});
export type AIExplanationRequest = z.infer<typeof AIExplanationRequestSchema>;

