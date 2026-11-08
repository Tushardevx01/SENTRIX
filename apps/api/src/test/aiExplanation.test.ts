import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildServer } from '../server.js';
import { aiService } from '../services/aiService.js';

describe('SENTRIX Module D: Grounded AI Explanation Tests', () => {
  let app: any;

  test.before(async () => {
    app = buildServer();
  });

  test.after(async () => {
    await app.close();
  });

  it('Scenario 1: Deterministic explanation grounds analysis in actual findings', async () => {
    const explanation = aiService.generateDeterministicExplanation({
      contextType: 'SCAN',
      target: 'http://apple-id-verify.xyz/login',
      findingsSummary: [
        'Brand Impersonation Detected: Apple',
        'Insecure Form Submission (HTTP)',
        'High-Risk Top-Level Domain (.xyz)',
      ],
      riskScore: 90,
      verdict: 'MALICIOUS',
    });

    assert.ok(explanation.summary.includes('MALICIOUS') || explanation.summary.includes('threat'));
    assert.ok(explanation.reasoning.length >= 3);
    assert.ok(explanation.precautions.length >= 2);
    assert.ok(explanation.limitations.length >= 1);

    // Verify groundedness: mentions Apple and Insecure Form
    assert.ok(explanation.reasoning.some((r) => r.includes('Apple')));
    assert.ok(explanation.reasoning.some((r) => r.includes('Insecure Form')));
  });

  it('Scenario 2: Benign scan generates reassuring guidance without false alarm', async () => {
    const explanation = aiService.generateDeterministicExplanation({
      contextType: 'SCAN',
      target: 'https://python.org',
      findingsSummary: ['Valid TLS Certificate', 'Authentic Organization'],
      riskScore: 10,
      verdict: 'BENIGN',
    });

    assert.ok(explanation.summary.toLowerCase().includes('benign'));
    assert.ok(explanation.reasoning.some((r) => r.toLowerCase().includes('authentic') || r.toLowerCase().includes('benign')));
  });

  it('Scenario 3: API POST /api/v1/ai/explain returns structured explanation', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/ai/explain',
      payload: {
        contextType: 'MESSAGE',
        target: 'SMS from Chase Bank',
        findingsSummary: ['Credential Harvesting', 'Urgency Tactic'],
        riskScore: 85,
        verdict: 'MALICIOUS',
      },
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.ok(body.summary);
    assert.ok(Array.isArray(body.reasoning));
    assert.ok(Array.isArray(body.precautions));
    assert.ok(Array.isArray(body.limitations));
  });

  it('Scenario 4: Validates payload and rejects missing contextType', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/ai/explain',
      payload: {
        target: 'https://example.com',
      },
    });

    assert.equal(res.statusCode, 400);
  });
});
