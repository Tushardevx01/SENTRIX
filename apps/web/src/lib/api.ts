import {
  type IScan,
  type IThreatReport,
  type DashboardStats,
  type ScanReportDetail,
  type AnalyzerStatusMap,
  type ScanStatus,
  type ThreatCategory,
  type VoteType,
  type IMessageAnalysis,
  type MessageChannel,
  type IRelatedThreats,
  type IThreatCampaign,
  type IThreatIndicator,
  type IBlockchainRecord,
  type IBlockchainVerification,
  type IAIExplanation,
} from '@sentrix/shared';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface ScanStatusResponse {
  scanId: string;
  status: ScanStatus;
  submittedUrl: string;
  normalizedDomain: string;
  retryCount?: number;
  analyzerStatuses?: AnalyzerStatusMap;
  error?: string;
  createdAt?: string;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = 25000
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: options.signal || controller.signal,
    });
    return res;
  } catch (err: any) {
    if (err.name === 'AbortError') {
      throw new Error(
        `Request timed out after ${Math.round(timeoutMs / 1000)}s. The security gateway or scanner engine may be waking up (cold boot). Please retry.`
      );
    }
    throw err;
  } finally {
    clearTimeout(id);
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMessage = `Request failed with status ${res.status}`;
    try {
      const data = await res.json();
      if (data?.message) {
        errorMessage = data.message;
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errorMessage);
  }
  return res.json();
}

export async function submitUrlScan(
  url: string,
  deepScan: boolean = false
): Promise<{ scanId: string; [key: string]: any }> {
  const res = await fetchWithTimeout(
    `${API_BASE_URL}/api/v1/scans`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, deepScan }),
    },
    35000
  );
  return handleResponse(res);
}

export async function fetchScanReport(id: string): Promise<ScanReportDetail> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/reports/${encodeURIComponent(id)}`);
  return handleResponse(res);
}

export async function fetchScanStatus(id: string): Promise<ScanStatusResponse> {
  const res = await fetchWithTimeout(
    `${API_BASE_URL}/api/v1/scans/${encodeURIComponent(id)}/results`,
    {},
    15000
  );
  return handleResponse(res);
}

export async function fetchScanHistory(
  limit: number = 50,
  skip: number = 0,
  domain?: string
): Promise<{ total: number; scans: IScan[] }> {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('skip', String(skip));
  if (domain) {
    params.set('domain', domain);
  }
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/scans?${params.toString()}`);
  return handleResponse(res);
}

export async function fetchThreats(
  query?: string,
  limit?: number
): Promise<{ threats: IScan[]; communityThreats: IThreatReport[] }> {
  const params = new URLSearchParams();
  if (query) {
    params.set('query', query);
  }
  if (limit) {
    params.set('limit', String(limit));
  }
  const queryString = params.toString() ? `?${params.toString()}` : '';
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/threats${queryString}`);
  return handleResponse(res);
}

export async function fetchCommunityReports(): Promise<{ reports: IThreatReport[] }> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/community/reports`);
  return handleResponse(res);
}

export async function submitCommunityReport(payload: {
  url: string;
  category: ThreatCategory;
  description: string;
  submitterEmail?: string;
}): Promise<{ report: IThreatReport; message: string }> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/community/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return handleResponse(res);
}

export async function voteCommunityReport(
  reportId: string,
  vote: 'UPVOTE' | 'DOWNVOTE' | VoteType
): Promise<{ message: string; vote: string }> {
  const res = await fetchWithTimeout(
    `${API_BASE_URL}/api/v1/community/reports/${encodeURIComponent(reportId)}/vote`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vote }),
    }
  );
  return handleResponse(res);
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/dashboard/stats`);
  return handleResponse(res);
}

// ==========================================
// MODULE A: AI SCAM & MESSAGE ANALYSIS
// ==========================================

export async function analyzeMessage(payload: {
  content: string;
  channel?: MessageChannel;
  sender?: string;
  metadata?: Record<string, any>;
}): Promise<IMessageAnalysis> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/messages/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return handleResponse(res);
}

export async function fetchMessageAnalysis(id: string): Promise<IMessageAnalysis> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/messages/${encodeURIComponent(id)}`);
  return handleResponse(res);
}

export async function fetchMessageAnalyses(
  limit: number = 20,
  skip: number = 0
): Promise<{ total: number; messages: IMessageAnalysis[] }> {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('skip', String(skip));
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/messages?${params.toString()}`);
  return handleResponse(res);
}

// ==========================================
// MODULE B: INTELLIGENT THREAT CORRELATION
// ==========================================

export async function fetchRelatedThreats(target: string): Promise<IRelatedThreats> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/correlations/related/${encodeURIComponent(target)}`);
  return handleResponse(res);
}

export async function fetchThreatCampaigns(): Promise<{ total: number; campaigns: IThreatCampaign[] }> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/correlations/campaigns`);
  return handleResponse(res);
}

export async function fetchThreatCampaign(id: string): Promise<IThreatCampaign> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/correlations/campaigns/${encodeURIComponent(id)}`);
  return handleResponse(res);
}

export async function fetchThreatIndicators(
  type?: string,
  limit: number = 50
): Promise<{ total: number; indicators: IThreatIndicator[] }> {
  const params = new URLSearchParams();
  if (type) params.set('type', type);
  params.set('limit', String(limit));
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/correlations/indicators?${params.toString()}`);
  return handleResponse(res);
}

// ==========================================
// MODULE C: BLOCKCHAIN DECENTRALIZED REGISTRY
// ==========================================

export async function registerOnBlockchain(
  reportId: string,
  reportType: 'SCAN' | 'MESSAGE' | 'THREAT_REPORT' = 'SCAN'
): Promise<IBlockchainRecord> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/blockchain/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reportId, reportType }),
  });
  return handleResponse(res);
}

export async function verifyOnBlockchain(reportId: string): Promise<IBlockchainVerification> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/blockchain/verify/${encodeURIComponent(reportId)}`);
  return handleResponse(res);
}

export async function fetchBlockchainRecords(
  limit: number = 20,
  skip: number = 0
): Promise<{ total: number; records: IBlockchainRecord[] }> {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('skip', String(skip));
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/blockchain/records?${params.toString()}`);
  return handleResponse(res);
}

export async function fetchBlockchainConfig(): Promise<{
  enabled: boolean;
  chainId: number;
  rpcUrl?: string;
  contractAddress?: string;
  isSimulated: boolean;
}> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/blockchain/config`);
  return handleResponse(res);
}

// ==========================================
// MODULE D: GROUNDED AI EXPLANATION
// ==========================================

export async function fetchAIExplanation(payload: {
  contextType: 'SCAN' | 'MESSAGE' | 'CAMPAIGN';
  scanId?: string;
  messageId?: string;
  target?: string;
  riskScore?: number;
  verdict?: string;
  findingsSummary?: string[];
  indicators?: Record<string, any>;
}): Promise<{ explanation: IAIExplanation; modelUsed: string; groundedFindings: string[] }> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/ai/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return handleResponse(res);
}
