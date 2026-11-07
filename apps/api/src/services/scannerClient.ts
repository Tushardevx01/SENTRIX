import {
  type ScannerAnalysisRequest,
  type ScannerAnalysisResponse,
} from '@sentrix/shared';
import { env } from '../utils/config.js';

export class ScannerClientError extends Error {
  constructor(
    message: string,
    public statusCode: number = 502,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ScannerClientError';
  }
}

export async function requestScannerAnalysis(
  payload: ScannerAnalysisRequest
): Promise<ScannerAnalysisResponse> {
  const targetEndpoint = `${env.SCANNER_INTERNAL_URL}/api/v1/analyze`;

  try {
    const response = await fetch(targetEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Scanner-Secret': env.SCANNER_API_SECRET,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30000), // 30s max timeout
    });

    if (!response.ok) {
      let errorBody: any;
      try {
        errorBody = await response.json();
      } catch {
        errorBody = await response.text();
      }

      if (response.status === 400 && errorBody?.error === 'SSRF_VIOLATION') {
        throw new ScannerClientError(
          errorBody.message || 'Target URL rejected due to security policy (SSRF / restricted network)',
          400,
          errorBody
        );
      }

      throw new ScannerClientError(
        `Scanner service returned HTTP ${response.status}: ${JSON.stringify(errorBody)}`,
        response.status === 401 ? 500 : response.status,
        errorBody
      );
    }

    const data = (await response.json()) as ScannerAnalysisResponse;
    return data;
  } catch (error: any) {
    if (error instanceof ScannerClientError) {
      throw error;
    }
    throw new ScannerClientError(
      `Unable to communicate with internal scanner engine: ${error?.message || error}`,
      503,
      { originalError: String(error) }
    );
  }
}
