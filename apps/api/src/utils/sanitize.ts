/**
 * Escapes characters with special meaning in regular expressions to prevent ReDoS
 * and unintended regex query injection in MongoDB / Mongoose queries.
 */
export function escapeRegex(input: string): string {
  if (typeof input !== 'string') return '';
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Validates and bounds pagination parameters to prevent negative skips
 * or massive limit requests from overwhelming the database.
 */
export function sanitizePagination(
  skipInput?: string | number,
  limitInput?: string | number,
  maxLimit = 100,
  defaultLimit = 20
): { skip: number; limit: number } {
  const parsedSkip = typeof skipInput === 'number' ? skipInput : parseInt(String(skipInput || '0'), 10);
  const parsedLimit = typeof limitInput === 'number' ? limitInput : parseInt(String(limitInput || defaultLimit), 10);

  const skip = Math.max(0, isNaN(parsedSkip) ? 0 : parsedSkip);
  const limit = Math.min(maxLimit, Math.max(1, isNaN(parsedLimit) ? defaultLimit : parsedLimit));

  return { skip, limit };
}
