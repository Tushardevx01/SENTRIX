import {
  type IScan,
  type IThreatReport,
  type DashboardStats,
  type ScanReportDetail,
  type ThreatCategory,
  type VoteType,
} from '@sentrix/shared';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

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
  const res = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, deepScan }),
  });
  return handleResponse(res);
}

export async function fetchScanReport(id: string): Promise<ScanReportDetail> {
  const res = await fetch(`${API_BASE_URL}/api/v1/reports/${encodeURIComponent(id)}`);
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
  const res = await fetch(`${API_BASE_URL}/api/v1/scans?${params.toString()}`);
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
  const res = await fetch(`${API_BASE_URL}/api/v1/threats${queryString}`);
  return handleResponse(res);
}

export async function fetchCommunityReports(): Promise<{ reports: IThreatReport[] }> {
  const res = await fetch(`${API_BASE_URL}/api/v1/community/reports`);
  return handleResponse(res);
}

export async function submitCommunityReport(payload: {
  url: string;
  category: ThreatCategory;
  description: string;
  submitterEmail?: string;
}): Promise<{ report: IThreatReport; message: string }> {
  const res = await fetch(`${API_BASE_URL}/api/v1/community/reports`, {
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
  const res = await fetch(`${API_BASE_URL}/api/v1/community/reports/${encodeURIComponent(reportId)}/vote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vote }),
  });
  return handleResponse(res);
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE_URL}/api/v1/dashboard/stats`);
  return handleResponse(res);
}
