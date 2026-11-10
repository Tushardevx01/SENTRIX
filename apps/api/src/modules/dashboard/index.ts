import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { ScanModel } from '../../models/Scan.js';
import { ThreatReportModel } from '../../models/ThreatReport.js';
import { VerdictEnum } from '@sentrix/shared';

export const dashboardRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // GET /api/v1/dashboard/stats - Real-time verified telemetry
  app.get('/stats', async (request, reply) => {
    const [
      totalScans,
      maliciousCount,
      suspiciousCount,
      benignCount,
      unverifiedCount,
      threatsReported,
      avgScoreResult,
      recentScans,
    ] = await Promise.all([
      ScanModel.countDocuments(),
      ScanModel.countDocuments({
        status: 'COMPLETED',
        verdict: { $in: [VerdictEnum.MALICIOUS, VerdictEnum.CONFIRMED_MALICIOUS] },
      }),
      ScanModel.countDocuments({ status: 'COMPLETED', verdict: VerdictEnum.SUSPICIOUS }),
      ScanModel.countDocuments({ status: 'COMPLETED', verdict: VerdictEnum.BENIGN }),
      ScanModel.countDocuments({ status: 'COMPLETED', verdict: VerdictEnum.UNVERIFIED_INFRASTRUCTURE }),
      ThreatReportModel.countDocuments(),
      ScanModel.aggregate([
        { $match: { status: 'COMPLETED' } },
        { $group: { _id: null, avgScore: { $avg: '$riskScore' } } },
      ]),
      ScanModel.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .select('_id submittedUrl normalizedDomain riskScore verdict status createdAt')
        .lean(),
    ]);

    const averageRiskScore = avgScoreResult.length > 0 ? Math.round(avgScoreResult[0].avgScore) : 0;

    return reply.send({
      totalScans,
      maliciousCount,
      suspiciousCount,
      benignCount,
      unverifiedCount,
      averageRiskScore,
      threatsReported,
      recentScans,
    });
  });
};
