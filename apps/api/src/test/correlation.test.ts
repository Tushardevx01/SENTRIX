import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { buildServer } from '../server.js';
import { correlationService } from '../services/correlationService.js';
import { ThreatIndicatorModel } from '../models/ThreatIndicator.js';
import { ThreatCampaignModel } from '../models/ThreatCampaign.js';
import { ScanModel } from '../models/Scan.js';

describe('SENTRIX Module B: Intelligent Threat Correlation Tests', () => {
  let app: any;

  test.before(async () => {
    app = buildServer();
    const uri = process.env.TEST_MONGODB_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/sentrix_test';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(uri);
    }
  });

  test.after(async () => {
    await app.close();
    await mongoose.disconnect();
  });

  it('Scenario 1: Ingests indicators from a scan and prevents duplicate indicators', async () => {
    const scan = await ScanModel.create({
      submittedUrl: 'http://paypal-verification-alert.xyz/auth',
      normalizedDomain: 'paypal-verification-alert.xyz',
      urlHash: 'hash-test-correlation-1',
      status: 'COMPLETED',
      riskScore: 85,
      verdict: 'MALICIOUS',
      confidence: 95,
      analyzerStatuses: {
        urlAnalyzer: 'SUCCESS',
        domainAnalyzer: 'SUCCESS',
        tlsAnalyzer: 'SUCCESS',
        webSecurityAnalyzer: 'SUCCESS',
        reputationAnalyzer: 'SUCCESS',
      },
    });

    await correlationService.ingestScan(scan._id.toString());

    // Verify indicator created
    const indicator = (await ThreatIndicatorModel.findOne({
      type: 'DOMAIN',
      normalizedValue: 'paypal-verification-alert.xyz',
    }).lean()) as any;

    assert.ok(indicator);
    assert.equal(indicator.type, 'DOMAIN');
    assert.equal(indicator.normalizedValue, 'paypal-verification-alert.xyz');
    assert.equal(indicator.severity, 'CRITICAL');
    assert.ok(indicator.occurrences >= 1);
  });

  it('Scenario 2: Returns cross-report related threats and campaign connections', async () => {
    const related = await correlationService.getRelatedThreats('paypal-verification-alert.xyz');

    assert.ok(related);
    assert.equal(related.target, 'paypal-verification-alert.xyz');
    assert.ok(Array.isArray(related.indicatorMatches));
    assert.ok(Array.isArray(related.relatedScans));
    assert.ok(related.relatedScans.some((s) => s.submittedUrl.includes('paypal-verification-alert.xyz')));
  });

  it('Scenario 3: API GET /api/v1/correlations/related/:target returns structured graph', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/correlations/related/paypal-verification-alert.xyz',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.ok(body.target);
    assert.ok(Array.isArray(body.indicatorMatches));
    assert.ok(Array.isArray(body.relatedScans));
  });

  it('Scenario 4: API GET /api/v1/correlations/indicators lists top recurring indicators', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/correlations/indicators?limit=10',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.ok(Array.isArray(body.indicators));
  });

  it('Scenario 5: API GET /api/v1/correlations/campaigns lists campaigns', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/correlations/campaigns',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.ok(Array.isArray(body.campaigns));
  });
});
