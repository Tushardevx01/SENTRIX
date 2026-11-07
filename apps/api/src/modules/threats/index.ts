import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { ScanModel } from '../../models/Scan.js';
import { ThreatReportModel } from '../../models/ThreatReport.js';
import { escapeRegex, sanitizePagination } from '../../utils/sanitize.js';

export const threatsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // GET /api/v1/threats - Global threat intelligence feed from verified scans & reports
  app.get('/', async (request, reply) => {
    const { query, limit } = request.query as Record<string, string>;
    const { limit: safeLimit } = sanitizePagination(0, limit, 100, 30);

    const searchFilter: Record<string, any> = {
      verdict: { $in: ['SUSPICIOUS', 'MALICIOUS'] },
    };

    if (query && typeof query === 'string') {
      const sanitizedQuery = escapeRegex(query.trim().slice(0, 100));
      if (sanitizedQuery) {
        searchFilter.$or = [
          { normalizedDomain: { $regex: sanitizedQuery, $options: 'i' } },
          { submittedUrl: { $regex: sanitizedQuery, $options: 'i' } },
        ];
      }
    }

    const threats = await ScanModel.find(searchFilter)
      .sort({ createdAt: -1 })
      .limit(safeLimit)
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
