import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { ScanModel } from '../../models/Scan.js';
import { ThreatReportModel } from '../../models/ThreatReport.js';

export const threatsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // GET /api/v1/threats - Global threat intelligence feed from verified scans & reports
  app.get('/', async (request, reply) => {
    const { query, limit = '30' } = request.query as Record<string, string>;
    const searchFilter: Record<string, any> = {
      verdict: { $in: ['SUSPICIOUS', 'MALICIOUS'] },
    };

    if (query) {
      searchFilter.$or = [
        { normalizedDomain: { $regex: query, $options: 'i' } },
        { submittedUrl: { $regex: query, $options: 'i' } },
      ];
    }

    const threats = await ScanModel.find(searchFilter)
      .sort({ createdAt: -1 })
      .limit(Math.min(100, Number(limit) || 30))
      .select('submittedUrl normalizedDomain riskScore verdict summary createdAt')
      .lean();

    const confirmedCommunityThreats = await ThreatReportModel.find({
      status: { $in: ['CONFIRMED', 'UNDER_REVIEW'] },
    })
      .sort({ reportCount: -1, createdAt: -1 })
      .limit(20)
      .lean();

    return reply.send({
      threats,
      communityThreats: confirmedCommunityThreats,
    });
  });
};
