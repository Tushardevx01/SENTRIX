import mongoose from 'mongoose';
import crypto from 'node:crypto';
import {
  type IThreatIndicator,
  type IThreatCampaign,
  type IRelatedThreats,
  type IndicatorType,
} from '@sentrix/shared';
import { ThreatIndicatorModel } from '../models/ThreatIndicator.js';
import { ThreatCampaignModel } from '../models/ThreatCampaign.js';
import { ScanModel } from '../models/Scan.js';
import { MessageAnalysisModel } from '../models/MessageAnalysis.js';
import { FindingModel } from '../models/Finding.js';

export class CorrelationService {
  /**
   * Ingests forensic findings from a completed URL scan to update indicator index.
   */
  public async ingestScan(scanId: string): Promise<void> {
    try {
      if (mongoose.connection.readyState !== 1) return;
      const scan = (await ScanModel.findById(scanId).lean()) as any;
      if (!scan) return;

      const findings = await FindingModel.find({ scanId }).lean();
      const severity =
        scan.verdict === 'MALICIOUS'
          ? 'CRITICAL'
          : scan.verdict === 'SUSPICIOUS'
          ? 'HIGH'
          : 'INFO';

      // 1. Index Domain indicator
      if (scan.normalizedDomain) {
        await this.upsertIndicator(
          'DOMAIN',
          scan.normalizedDomain,
          severity,
          scan._id,
          undefined,
          scan.verdict
        );
      }

      // 2. Index IP indicator if available
      if (scan.summary?.ipAddress) {
        await this.upsertIndicator(
          'IP',
          scan.summary.ipAddress,
          severity,
          scan._id,
          undefined,
          scan.verdict
        );
      }

      // 3. Index Brand Impersonation findings
      for (const f of findings) {
        if (f.title.includes('Impersonation') || f.title.includes('Typosquatting')) {
          const brandMatch = f.title.split(':')[1]?.trim() || f.description.match(/(?:brand|entity)\s*([A-Za-z0-9_-]+)/i)?.[1];
          if (brandMatch) {
            await this.upsertIndicator(
              'BRAND',
              brandMatch,
              f.severity,
              scan._id,
              undefined,
              scan.verdict
            );
          }
        }
      }

      // 4. Update Campaigns
      await this.evaluateCampaignLink(scan);
    } catch (err) {
      console.warn('[CorrelationService] Error ingesting scan:', (err as Error).message);
    }
  }

  /**
   * Queries multi-source intelligence to find all related threat reports,
   * campaigns, and shared indicators for a target URL, domain, or indicator string.
   */
  public async getRelatedThreats(target: string): Promise<IRelatedThreats> {
    const cleanTarget = target.trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

    // 1. Find matching indicators
    const matchingIndicators = await ThreatIndicatorModel.find({
      normalizedValue: { $regex: cleanTarget, $options: 'i' },
    })
      .sort({ occurrences: -1 })
      .limit(10)
      .lean();

    // 2. Query related scans
    const relatedScans = await ScanModel.find({
      $or: [
        { normalizedDomain: cleanTarget },
        { submittedUrl: { $regex: cleanTarget, $options: 'i' } },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(8)
      .select('_id submittedUrl verdict riskScore createdAt')
      .lean();

    // 3. Query related messages
    const relatedMessages = await MessageAnalysisModel.find({
      $or: [
        { 'extractedIndicators.domains': cleanTarget },
        { 'extractedIndicators.urls': { $regex: cleanTarget, $options: 'i' } },
        { preview: { $regex: cleanTarget, $options: 'i' } },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(8)
      .select('_id preview classification riskScore createdAt')
      .lean();

    // 4. Query active campaigns
    const campaigns = await ThreatCampaignModel.find({
      $or: [
        { 'indicators.value': cleanTarget },
        { 'relatedIncidents.target': { $regex: cleanTarget, $options: 'i' } },
      ],
    })
      .sort({ updatedAt: -1 })
      .limit(5)
      .lean();

    return {
      target,
      indicatorMatches: matchingIndicators as unknown as IThreatIndicator[],
      campaigns: campaigns as unknown as IThreatCampaign[],
      relatedScans: relatedScans.map((s: any) => ({
        _id: s._id.toString(),
        submittedUrl: s.submittedUrl,
        verdict: s.verdict,
        riskScore: s.riskScore,
        createdAt: s.createdAt.toISOString(),
      })),
      relatedMessages: relatedMessages.map((m: any) => ({
        _id: m._id.toString(),
        preview: m.preview,
        classification: m.classification,
        riskScore: m.riskScore,
        createdAt: m.createdAt.toISOString(),
      })),
    };
  }

  /**
   * Retrieves top recurring threat indicators across the platform.
   */
  public async getTopIndicators(limit = 30): Promise<IThreatIndicator[]> {
    const indicators = await ThreatIndicatorModel.find()
      .sort({ occurrences: -1, lastSeen: -1 })
      .limit(limit)
      .lean();
    return indicators as unknown as IThreatIndicator[];
  }

  /**
   * Retrieves active threat campaigns.
   */
  public async getCampaigns(limit = 20): Promise<IThreatCampaign[]> {
    const campaigns = await ThreatCampaignModel.find()
      .sort({ updatedAt: -1 })
      .limit(limit)
      .lean();
    return campaigns as unknown as IThreatCampaign[];
  }

  /**
   * Retrieves a specific campaign by ID.
   */
  public async getCampaignById(campaignId: string): Promise<IThreatCampaign | null> {
    const campaign = await ThreatCampaignModel.findOne({
      $or: [
        { campaignId },
        ...(mongoose.Types.ObjectId.isValid(campaignId) ? [{ _id: campaignId }] : []),
      ],
    }).lean();
    return (campaign as unknown as IThreatCampaign) || null;
  }

  private async upsertIndicator(
    type: IndicatorType,
    value: string,
    severity: any,
    scanId?: any,
    messageId?: any,
    tag?: string
  ): Promise<void> {
    const normalizedValue = value.toLowerCase().trim();
    const updateQuery: any = {
      $set: {
        value,
        severity,
        lastSeen: new Date(),
      },
      $inc: { occurrences: 1 },
      $setOnInsert: {
        firstSeen: new Date(),
      },
    };

    const addSet: any = {};
    if (scanId) addSet.relatedScanIds = scanId;
    if (messageId) addSet.relatedMessageIds = messageId;
    if (tag) addSet.tags = tag;
    if (Object.keys(addSet).length > 0) {
      updateQuery.$addToSet = addSet;
    }

    await ThreatIndicatorModel.findOneAndUpdate(
      { type, normalizedValue },
      updateQuery,
      { upsert: true }
    );
  }

  private async evaluateCampaignLink(scan: any): Promise<void> {
    if (scan.verdict !== 'MALICIOUS' && scan.verdict !== 'SUSPICIOUS') return;

    // Check if domain or brand has existing related scans
    const existing = await ScanModel.find({
      normalizedDomain: scan.normalizedDomain,
      _id: { $ne: scan._id },
      verdict: { $in: ['MALICIOUS', 'SUSPICIOUS'] },
    }).limit(5).lean();

    if (existing.length >= 1) {
      const campaignId = `CAMP-${crypto.createHash('md5').update(scan.normalizedDomain).digest('hex').slice(0, 8).toUpperCase()}`;
      const campaignName = `Operation ${scan.normalizedDomain.split('.')[0].toUpperCase()} Impersonation Cluster`;

      const incidents = [
        ...existing.map((e: any) => ({
          id: e._id.toString(),
          target: e.submittedUrl,
          verdict: e.verdict,
          type: 'SCAN' as const,
          timestamp: e.createdAt,
        })),
        {
          id: scan._id.toString(),
          target: scan.submittedUrl,
          verdict: scan.verdict,
          type: 'SCAN' as const,
          timestamp: scan.createdAt,
        },
      ];

      await ThreatCampaignModel.findOneAndUpdate(
        { campaignId },
        {
          $set: {
            name: campaignName,
            threatType: scan.summary?.threatTypes?.[0] || 'PHISHING',
            confidence: 90,
            summary: `Automated correlation detected ${incidents.length} related attacks targeting domain infrastructure associated with ${scan.normalizedDomain}.`,
            indicators: [{ type: 'DOMAIN', value: scan.normalizedDomain }],
            relatedIncidents: incidents,
          },
        },
        { upsert: true }
      );
    }
  }
}

export const correlationService = new CorrelationService();
