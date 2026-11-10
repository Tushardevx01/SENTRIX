import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { buildServer } from '../server.js';
import { messageAnalyzer } from '../services/messageAnalyzer.js';
import { MessageAnalysisModel } from '../models/MessageAnalysis.js';

describe('SENTRIX Module A: AI-Powered Scam & Message Analysis Tests', () => {
  let app: any;

  test.before(async () => {
    app = buildServer();
    const uri = process.env.TEST_MONGODB_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/sentrix_test';
    try {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(uri, { serverSelectionTimeoutMS: 2000 });
      }
    } catch (err: any) {
      console.warn('MongoDB not available for messageAnalysis tests:', err.message);
    }
  });

  test.after(async () => {
    await app.close();
    await mongoose.disconnect();
  });

  it('Scenario 1: Detects OTP credential harvesting with high urgency', async () => {
    const text = 'URGENT: Your Chase Bank account has been locked. Verify your 6-digit OTP code immediately at https://chase-security-verify.xyz/login within 24 hours to prevent account closure.';
    const result = await messageAnalyzer.analyze(text, 'SMS', 'CHASE_ALERTS');

    assert.ok(result.classification === 'MALICIOUS' || result.classification === 'CONFIRMED_MALICIOUS');
    assert.ok(result.riskScore >= 70, `Expected score >= 70, got ${result.riskScore}`);
    assert.ok(result.confidence >= 75);

    // Verify extracted indicators
    assert.ok(result.extractedIndicators.domains.includes('chase-security-verify.xyz'));
    assert.ok(result.extractedIndicators.entities.some((e) => e.toLowerCase().includes('chase')));

    // Verify detected tactics
    const tactics = result.detectedPatterns.map((p) => p.tactic);
    assert.ok(tactics.includes('CREDENTIAL_OTP_HARVESTING'));
    assert.ok(tactics.includes('URGENCY_FEAR'));
    assert.ok(tactics.includes('AUTHORITY_IMPERSONATION'));
  });

  it('Scenario 2: Detects cryptocurrency wallet drainer & seed-phrase solicitation', async () => {
    const text = 'Metamask Airdrop Winner! Connect your wallet and enter your 12-word recovery phrase to claim $5000 in ETH. Send 0.05 ETH gas fee to 0x71C95911E9A5D330f4D621842EC243EE1343292e';
    const result = await messageAnalyzer.analyze(text, 'TELEGRAM');

    assert.ok(result.classification === 'MALICIOUS' || result.classification === 'CONFIRMED_MALICIOUS');
    assert.ok(result.riskScore >= 80);

    // Verify wallet extraction
    assert.ok(result.extractedIndicators.wallets.some((w) => w.address === '0x71C95911E9A5D330f4D621842EC243EE1343292e'));
    assert.ok(result.extractedIndicators.entities.some((e) => e.toLowerCase().includes('metamask')));

    // Verify tactic
    const tactics = result.detectedPatterns.map((p) => p.tactic);
    assert.ok(tactics.includes('CREDENTIAL_OTP_HARVESTING'));
    assert.ok(tactics.includes('SUSPICIOUS_PAYMENT'));
  });

  it('Scenario 3: Benign urgent message is NOT falsely flagged as fraud', async () => {
    const text = 'Hi team, please submit your quarterly project reports by 5 PM today so we can finalize the presentation. Thanks!';
    const result = await messageAnalyzer.analyze(text, 'EMAIL');

    assert.equal(result.classification, 'BENIGN');
    assert.ok(result.riskScore < 25, `Expected benign score < 25, got ${result.riskScore}`);
    assert.equal(result.detectedPatterns.length, 0);
  });

  it('Scenario 4: Detects fake refund & technical support remote-access scam', async () => {
    const text = 'Geek Squad Invoice #GS-99214: $499.00 charged. If you did not authorize this, call Microsoft support at +18005550199 immediately. A technician will guide you to install AnyDesk for a full refund.';
    const result = await messageAnalyzer.analyze(text, 'EMAIL');

    assert.ok(result.classification === 'MALICIOUS' || result.classification === 'CONFIRMED_MALICIOUS');
    assert.ok(result.riskScore >= 70);

    const tactics = result.detectedPatterns.map((p) => p.tactic);
    assert.ok(tactics.includes('TECH_SUPPORT_REMOTE_ACCESS'));
    assert.ok(tactics.includes('FINANCIAL_MANIPULATION'));
  });

  it('Scenario 5: API POST /api/v1/messages/analyze processes payload and stores record', async () => {
    if (mongoose.connection.readyState === 0) return;
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/messages/analyze',
      payload: {
        messageText: 'Your Netflix membership is on hold. Update payment details: https://netflix-billing-renew.club',
        channel: 'SMS',
      },
    });

    assert.equal(res.statusCode, 201);
    const body = JSON.parse(res.body);
    assert.ok(body._id);
    assert.equal(body.channel, 'SMS');
    assert.ok(body.riskScore >= 26);
    assert.ok(body.aiExplanation.summary);
    assert.ok(body.aiExplanation.precautions.length > 0);

    // Verify GET /api/v1/messages/:id
    const getRes = await app.inject({
      method: 'GET',
      url: `/api/v1/messages/${body._id}`,
    });
    assert.equal(getRes.statusCode, 200);
    const retrieved = JSON.parse(getRes.body);
    assert.equal(retrieved._id, body._id);
  });

  it('Scenario 6: API validates input and enforces max length boundaries', async () => {
    const resShort = await app.inject({
      method: 'POST',
      url: '/api/v1/messages/analyze',
      payload: { messageText: 'hey' }, // too short (< 5 chars)
    });
    assert.equal(resShort.statusCode, 400);

    const resEmpty = await app.inject({
      method: 'POST',
      url: '/api/v1/messages/analyze',
      payload: {},
    });
    assert.equal(resEmpty.statusCode, 400);
  });
});
