import { VerdictEnum, RiskThresholds, type Verdict } from '../types/index.js';

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
 * Derives verdict from risk score and analysis state
 */
export function getVerdictFromScore(score: number, isComplete: boolean = true): Verdict {
  if (!isComplete) return VerdictEnum.INCONCLUSIVE;
  if (score >= RiskThresholds.CONFIRMED_MALICIOUS_MIN) return VerdictEnum.CONFIRMED_MALICIOUS;
  if (score >= RiskThresholds.MALICIOUS_MIN) return VerdictEnum.MALICIOUS;
  if (score > RiskThresholds.BENIGN_MAX) return VerdictEnum.SUSPICIOUS;
  return VerdictEnum.BENIGN;
}
