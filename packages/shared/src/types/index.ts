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
  CONFIRMED_MALICIOUS: 'CONFIRMED_MALICIOUS',
  INCONCLUSIVE: 'INCONCLUSIVE',
  UNVERIFIED_INFRASTRUCTURE: 'UNVERIFIED_INFRASTRUCTURE',
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
  CONFIRMED_MALICIOUS_MIN: 85,
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
  unverifiedCount?: number;
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

// ==========================================
// Module A: Message & Scam Analysis Types
// ==========================================

export const MessageChannelEnum = {
  SMS: 'SMS',
  WHATSAPP: 'WHATSAPP',
  EMAIL: 'EMAIL',
  TELEGRAM: 'TELEGRAM',
  SOCIAL_MEDIA: 'SOCIAL_MEDIA',
  OTHER: 'OTHER',
} as const;
export type MessageChannel = (typeof MessageChannelEnum)[keyof typeof MessageChannelEnum];

export const SocialEngineeringTacticEnum = {
  URGENCY_FEAR: 'URGENCY_FEAR',
  AUTHORITY_IMPERSONATION: 'AUTHORITY_IMPERSONATION',
  FINANCIAL_MANIPULATION: 'FINANCIAL_MANIPULATION',
  CREDENTIAL_OTP_HARVESTING: 'CREDENTIAL_OTP_HARVESTING',
  SUSPICIOUS_PAYMENT: 'SUSPICIOUS_PAYMENT',
  UNREALISTIC_REWARD: 'UNREALISTIC_REWARD',
  TECH_SUPPORT_REMOTE_ACCESS: 'TECH_SUPPORT_REMOTE_ACCESS',
} as const;
export type SocialEngineeringTactic = (typeof SocialEngineeringTacticEnum)[keyof typeof SocialEngineeringTacticEnum];

export interface ISocialEngineeringFinding {
  tactic: SocialEngineeringTactic;
  severity: FindingSeverity;
  title: string;
  description: string;
  matchedPatterns: string[];
}

export interface IExtractedIndicators {
  urls: string[];
  domains: string[];
  emails: string[];
  phones: string[];
  wallets: Array<{ address: string; network: string }>;
  paymentRefs: string[];
  entities: string[];
}

export interface IThreatIntelMatch {
  indicatorType: string;
  indicatorValue: string;
  matchSource: string;
  severity: FindingSeverity;
  details: string;
}

export interface IAIExplanation {
  summary: string;
  reasoning: string[];
  precautions: string[];
  limitations: string[];
}

export interface IMessageAnalysis {
  _id: string;
  messageHash: string;
  channel: MessageChannel;
  senderInfo?: string;
  preview: string;
  classification: Verdict;
  riskScore: number;
  confidence: number;
  detectedPatterns: ISocialEngineeringFinding[];
  extractedIndicators: IExtractedIndicators;
  threatIntelMatches: IThreatIntelMatch[];
  aiExplanation: IAIExplanation;
  createdAt: string;
}

// ==========================================
// Module B: Threat Correlation Types
// ==========================================

export const IndicatorTypeEnum = {
  DOMAIN: 'DOMAIN',
  IP: 'IP',
  WALLET: 'WALLET',
  EMAIL: 'EMAIL',
  PHONE: 'PHONE',
  URL_PATTERN: 'URL_PATTERN',
  BRAND: 'BRAND',
} as const;
export type IndicatorType = (typeof IndicatorTypeEnum)[keyof typeof IndicatorTypeEnum];

export interface IThreatIndicator {
  _id: string;
  type: IndicatorType;
  value: string;
  normalizedValue: string;
  severity: FindingSeverity;
  firstSeen: string;
  lastSeen: string;
  occurrences: number;
  relatedScanIds: string[];
  relatedMessageIds: string[];
  relatedReportIds: string[];
  tags: string[];
}

export interface IThreatCampaign {
  _id: string;
  campaignId: string;
  name: string;
  threatType: string;
  confidence: number;
  indicators: Array<{ type: IndicatorType; value: string }>;
  relatedIncidents: Array<{
    id: string;
    target: string;
    verdict: Verdict;
    type: 'SCAN' | 'MESSAGE' | 'REPORT';
    timestamp: string;
  }>;
  summary: string;
  createdAt: string;
  updatedAt: string;
}

export interface IRelatedThreats {
  target: string;
  indicatorMatches: IThreatIndicator[];
  campaigns: IThreatCampaign[];
  relatedScans: Array<{
    _id: string;
    submittedUrl: string;
    verdict: Verdict;
    riskScore: number;
    createdAt: string;
  }>;
  relatedMessages: Array<{
    _id: string;
    preview: string;
    classification: Verdict;
    riskScore: number;
    createdAt: string;
  }>;
}

// ==========================================
// Module C: Web3 Blockchain Registry Types
// ==========================================

export const BlockchainRecordStatusEnum = {
  PENDING: 'PENDING',
  CONFIRMED: 'CONFIRMED',
  SIMULATED: 'SIMULATED',
  FAILED: 'FAILED',
} as const;
export type BlockchainRecordStatus = (typeof BlockchainRecordStatusEnum)[keyof typeof BlockchainRecordStatusEnum];

export const OnChainRecordStatusEnum = {
  ACTIVE: 'ACTIVE',
  DISPUTED: 'DISPUTED',
  REVISED: 'REVISED',
  REVOKED: 'REVOKED',
} as const;
export type OnChainRecordStatus = (typeof OnChainRecordStatusEnum)[keyof typeof OnChainRecordStatusEnum];

export interface IBlockchainRecord {
  _id: string;
  reportId: string;
  reportType: 'SCAN' | 'MESSAGE' | 'THREAT_REPORT';
  target: string;
  reportHash: string; // 0x-prefixed 32-byte hex hash
  canonicalData: Record<string, unknown>;
  txHash: string;
  blockNumber: number;
  blockTimestamp: number;
  contractAddress: string;
  chainId: number;
  networkName: string;
  reporterAddress: string;
  status: BlockchainRecordStatus;
  isSimulated?: boolean;
  metadataUri?: string;
  onChainStatus?: OnChainRecordStatus;
  revisionHash?: string;
  disputeCount?: number;
  createdAt: string;
}

export interface IBlockchainVerification {
  verified: boolean;
  reportId: string;
  calculatedHash: string;
  onChainHash: string;
  hashesMatch: boolean;
  isSimulated?: boolean;
  mode?: 'ON_CHAIN' | 'SIMULATED';
  blockNumber?: number;
  blockTimestamp?: number;
  txHash?: string;
  contractAddress?: string;
  networkName?: string;
  reporterAddress?: string;
  category?: string;
  severityScore?: number;
  metadataUri?: string;
  onChainStatus?: OnChainRecordStatus;
  revisionHash?: string;
  disputeCount?: number;
  timestampDate?: string;
  failureReason?: string;
}

