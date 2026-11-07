import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { escapeRegex, sanitizePagination } from '../utils/sanitize.js';
import { buildServer } from '../server.js';
import { ThreatReportModel } from '../models/ThreatReport.js';
import { ThreatVoteModel } from '../models/ThreatVote.js';

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

  it('Community voting rejects invalid report ID and invalid vote payload', async () => {
    const app = buildServer();

    // 1. Invalid report ID format
    const resInvalidId = await app.inject({
      method: 'POST',
      url: '/api/v1/community/reports/not-an-objectid/vote',
      payload: { vote: 'UPVOTE' },
    });
    assert.equal(resInvalidId.statusCode, 400);
    const bodyId = JSON.parse(resInvalidId.body);
    assert.equal(bodyId.error, 'VALIDATION_ERROR');
    assert.match(bodyId.message, /Invalid threat report ID format/);

    // 2. Invalid vote enum
    const validObjectId = new mongoose.Types.ObjectId().toHexString();
    const resInvalidVote = await app.inject({
      method: 'POST',
      url: `/api/v1/community/reports/${validObjectId}/vote`,
      payload: { vote: 'SUPER_UPVOTE' },
    });
    assert.equal(resInvalidVote.statusCode, 400);
    const bodyVote = JSON.parse(resInvalidVote.body);
    assert.equal(bodyVote.error, 'VALIDATION_ERROR');

    await app.close();
  });

  it('Community voting derives server-controlled voter identity and prevents session rotation bypass', async () => {
    const app = buildServer();
    const dummyReportId = new mongoose.Types.ObjectId();

    // Stub ThreatReportModel.findById
    const originalFindById = ThreatReportModel.findById;
    (ThreatReportModel as any).findById = async () => ({
      _id: dummyReportId,
      submittedUrl: 'https://phish.example.com',
    });

    // Track recorded votes
    const recordedFilters: any[] = [];
    const originalFindOneAndUpdate = ThreatVoteModel.findOneAndUpdate;
    (ThreatVoteModel as any).findOneAndUpdate = async (filter: any, update: any) => {
      recordedFilters.push({ filter, update });
      return { reportId: filter.reportId, userId: filter.userId, vote: update.vote };
    };

    try {
      const testIp = '198.51.100.42';
      const expectedVoterId = crypto.createHash('sha256').update(`voter:${testIp}`).digest('hex').slice(0, 32);

      // Vote 1 with session A
      const res1 = await app.inject({
        method: 'POST',
        url: `/api/v1/community/reports/${dummyReportId}/vote`,
        headers: {
          'x-forwarded-for': testIp,
          'x-session-id': 'client-session-AAAA',
        },
        payload: {
          vote: 'UPVOTE',
          sessionIdentifier: 'client-session-AAAA',
        },
      });
      assert.equal(res1.statusCode, 200);

      // Vote 2 from same IP with rotated session B (attacker trying to double-vote)
      const res2 = await app.inject({
        method: 'POST',
        url: `/api/v1/community/reports/${dummyReportId}/vote`,
        headers: {
          'x-forwarded-for': testIp,
          'x-session-id': 'client-session-BBBB-rotated',
        },
        payload: {
          vote: 'DOWNVOTE',
          sessionIdentifier: 'client-session-BBBB-rotated',
        },
      });
      assert.equal(res2.statusCode, 200);

      // Verify both votes were keyed to the EXACT SAME server-derived voter identity
      assert.equal(recordedFilters.length, 2);
      assert.equal(recordedFilters[0].filter.userId, expectedVoterId);
      assert.equal(recordedFilters[1].filter.userId, expectedVoterId);
      assert.notEqual(recordedFilters[0].filter.userId, 'client-session-AAAA');
      assert.notEqual(recordedFilters[1].filter.userId, 'client-session-BBBB-rotated');
    } finally {
      ThreatReportModel.findById = originalFindById;
      ThreatVoteModel.findOneAndUpdate = originalFindOneAndUpdate;
      await app.close();
    }
  });

  it('Community voting enforces route-level rate limiting (20 votes per minute per IP)', async () => {
    const app = buildServer();
    const dummyReportId = new mongoose.Types.ObjectId();

    const originalFindById = ThreatReportModel.findById;
    (ThreatReportModel as any).findById = async () => ({ _id: dummyReportId });

    const originalFindOneAndUpdate = ThreatVoteModel.findOneAndUpdate;
    (ThreatVoteModel as any).findOneAndUpdate = async (filter: any, update: any) => ({
      reportId: filter.reportId,
      userId: filter.userId,
      vote: update.vote,
    });

    try {
      const testIp = '198.51.100.99';
      let hit429 = false;

      // Submit 25 votes in rapid succession
      for (let i = 0; i < 25; i++) {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/community/reports/${dummyReportId}/vote`,
          headers: { 'x-forwarded-for': testIp },
          payload: { vote: 'UPVOTE' },
        });

        if (res.statusCode === 429) {
          hit429 = true;
          const body = JSON.parse(res.body);
          assert.equal(body.error, 'RATE_LIMIT_EXCEEDED');
          break;
        }
      }

      assert.equal(hit429, true, 'Expected rate limit (429) to be triggered on excessive voting');
    } finally {
      ThreatReportModel.findById = originalFindById;
      ThreatVoteModel.findOneAndUpdate = originalFindOneAndUpdate;
      await app.close();
    }
  });
});
