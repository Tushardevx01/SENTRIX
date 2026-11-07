import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { escapeRegex, sanitizePagination } from '../utils/sanitize.js';
import { buildServer } from '../server.js';

describe('Fastify Security & Input Sanitization Tests', () => {
  it('escapeRegex neutralizes all regex metacharacters', () => {
    const dangerousInput = '.*.*.*.*.*[a-z]+(test)?^${}|\\';
    const sanitized = escapeRegex(dangerousInput);

    assert.equal(
      sanitized,
      '\\.\\*\\.\\*\\.\\*\\.\\*\\.\\*\\[a-z\\]\\+\\(test\\)\\?\\^\\$\\{\\}\\|\\\\'
    );

    // Verify sanitized string behaves as literal in RegExp
    const re = new RegExp(sanitized);
    assert.equal(re.test(dangerousInput), true);
    assert.equal(re.test('arbitrary matching text'), false);
  });

  it('sanitizePagination bounds negative, NaN, and excessive limits', () => {
    // Negative skip is clamped to 0
    const neg = sanitizePagination('-20', '-5', 100, 20);
    assert.equal(neg.skip, 0);
    assert.equal(neg.limit, 1); // limit min bounded to 1

    // Massive limit is capped to maxLimit (100)
    const massive = sanitizePagination('50', '999999', 100, 20);
    assert.equal(massive.skip, 50);
    assert.equal(massive.limit, 100);

    // Malformed/garbage input falls back safely
    const malformed = sanitizePagination('not-a-number', 'also-garbage', 100, 20);
    assert.equal(malformed.skip, 0);
    assert.equal(malformed.limit, 20);
  });

  it('Fastify server exposes health endpoint', async () => {
    const app = buildServer();
    const res = await app.inject({
      method: 'GET',
      url: '/health',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.status, 'healthy');
    assert.equal(body.service, 'sentrix-api');
    await app.close();
  });

  it('Fastify error handler redacts internal 500 error messages', async () => {
    const app = buildServer();

    // Register a test route that throws an internal error leaking DB connection string
    app.get('/test-internal-error', async () => {
      const err = new Error('FATAL: MongoDB connection to mongodb://admin:secretPass@internal-cluster:27017 failed');
      (err as any).statusCode = 500;
      throw err;
    });

    const res = await app.inject({
      method: 'GET',
      url: '/test-internal-error',
    });

    assert.equal(res.statusCode, 500);
    const body = JSON.parse(res.body);
    assert.equal(body.error, 'INTERNAL_SERVER_ERROR');
    // Ensure sensitive internal message was NOT leaked
    assert.equal(body.message, 'An unexpected internal server error occurred');
    assert.equal(res.body.includes('secretPass'), false);
    assert.equal(res.body.includes('internal-cluster'), false);

    await app.close();
  });
});
