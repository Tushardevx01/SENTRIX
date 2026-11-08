import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { buildServer } from '../server.js';
import { blockchainService } from '../services/blockchainService.js';
import { ScanModel } from '../models/Scan.js';
import { BlockchainRecordModel } from '../models/BlockchainRecord.js';

describe('SENTRIX Module C: Web3 Blockchain Threat Registry Tests', () => {
  let app: any;

  test.before(async () => {
    app = buildServer();
    const uri = process.env.TEST_MONGODB_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/sentrix_test';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(uri);
    }
  });

  test.after(async () => {
    blockchainService.destroy();
    await app.close();
    await mongoose.disconnect();
  });

  it('Scenario 1: Generates deterministic canonical SHA-256 commitment regardless of key ordering', () => {
    const payloadA = { b: 2, a: 1, c: { z: 10, y: 9 } };
    const payloadB = { a: 1, c: { y: 9, z: 10 }, b: 2 };

    const commitA = blockchainService.generateCanonicalCommitment(payloadA);
    const commitB = blockchainService.generateCanonicalCommitment(payloadB);

    assert.equal(commitA.hashHex, commitB.hashHex);
    assert.equal(commitA.bytes32, commitB.bytes32);
    assert.match(commitA.bytes32, /^0x[a-f0-9]{64}$/);
  });

  it('Scenario 2: Registers threat report commitment and stores immutable receipt', async () => {
    const scan = await ScanModel.create({
      submittedUrl: 'http://metamask-security-drainer.cc/claim',
      normalizedDomain: 'metamask-security-drainer.cc',
      urlHash: 'hash-test-blockchain-1',
      status: 'COMPLETED',
      riskScore: 100,
      verdict: 'MALICIOUS',
      confidence: 99,
      analyzerStatuses: {
        urlAnalyzer: 'SUCCESS',
        domainAnalyzer: 'SUCCESS',
        tlsAnalyzer: 'SUCCESS',
        webSecurityAnalyzer: 'SUCCESS',
        reputationAnalyzer: 'SUCCESS',
      },
    });

    const record = await blockchainService.registerReport(scan._id.toString(), 'SCAN');

    assert.ok(record);
    assert.equal(record.reportId, scan._id.toString());
    assert.equal(record.reportType, 'SCAN');
    assert.match(record.reportHash, /^0x[a-f0-9]{64}$/);
    assert.match(record.txHash, /^0x[a-f0-9]{64}$/);
    assert.ok(record.blockNumber >= 1);
    assert.ok(record.contractAddress.startsWith('0x'));
    assert.equal(record.status, 'CONFIRMED');

    // Verify idempotency: duplicate registration returns existing record
    const dupRecord = await blockchainService.registerReport(scan._id.toString(), 'SCAN');
    assert.equal(dupRecord.txHash, record.txHash);
    assert.equal(dupRecord.reportHash, record.reportHash);
  });

  it('Scenario 3: Independently verifies report commitment matches on-chain state', async () => {
    const existing = (await BlockchainRecordModel.findOne().lean()) as any;
    assert.ok(existing, 'Expected at least one blockchain record');

    const verification = await blockchainService.verifyReport(existing.reportId);

    assert.equal(verification.verified, true);
    assert.equal(verification.hashesMatch, true);
    assert.equal(verification.calculatedHash, existing.reportHash.toLowerCase());
    assert.equal(verification.onChainHash, existing.reportHash.toLowerCase());
    assert.ok(verification.txHash);
    assert.ok(verification.contractAddress);
  });

  it('Scenario 4: Rejects verification if report has not been registered', async () => {
    const fakeId = new mongoose.Types.ObjectId().toString();
    const verification = await blockchainService.verifyReport(fakeId);

    assert.equal(verification.verified, false);
    assert.equal(verification.hashesMatch, false);
    assert.ok(verification.failureReason);
  });

  it('Scenario 5: API POST /api/v1/blockchain/register and GET /verify/:id work end to end', async () => {
    const scan = await ScanModel.create({
      submittedUrl: 'https://seed-phrase-phish.net/connect',
      normalizedDomain: 'seed-phrase-phish.net',
      urlHash: 'hash-test-blockchain-api',
      status: 'COMPLETED',
      riskScore: 90,
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

    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/blockchain/register',
      payload: {
        reportId: scan._id.toString(),
        reportType: 'SCAN',
      },
    });

    assert.equal(regRes.statusCode, 201);
    const regBody = JSON.parse(regRes.body);
    assert.ok(regBody.record.txHash);
    assert.ok(regBody.record.reportHash);

    // Verify via GET endpoint
    const verifyRes = await app.inject({
      method: 'GET',
      url: `/api/v1/blockchain/verify/${scan._id.toString()}`,
    });

    assert.equal(verifyRes.statusCode, 200);
    const verifyBody = JSON.parse(verifyRes.body);
    assert.equal(verifyBody.verified, true);
    assert.equal(verifyBody.hashesMatch, true);
  });

  it('Scenario 6: API GET /api/v1/blockchain/config returns valid network parameters', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/blockchain/config',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.ok(body.networkName);
    assert.ok(body.chainId);
    assert.ok(body.contractAddress.startsWith('0x'));
  });
});
