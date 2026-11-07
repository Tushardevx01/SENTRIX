import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import {
  ThreatReportCreateSchema,
  ThreatVoteCreateSchema,
  normalizeUrl,
  ThreatReportStatusEnum,
  VoteTypeEnum,
} from '@sentrix/shared';
import { ThreatReportModel } from '../../models/ThreatReport.js';
import { ThreatVoteModel } from '../../models/ThreatVote.js';

/**
 * Derives a deterministic, server-controlled voter identity from client IP.
 * Mitigates client session identifier rotation and prevents voting fraud.
 */
function deriveVoterIdentity(ip: string): string {
  const normalizedIp = ip || '127.0.0.1';
  return crypto.createHash('sha256').update(`voter:${normalizedIp}`).digest('hex').slice(0, 32);
}

export const communityRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/community/reports - Submit community threat report
  app.post('/reports', async (request, reply) => {
    const parseResult = ThreatReportCreateSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid threat report payload',
        details: parseResult.error.issues,
      });
    }

    const { url, category, description, submitterEmail } = parseResult.data;
    const { normalizedUrl, normalizedDomain } = normalizeUrl(url);
    const urlHash = crypto.createHash('sha256').update(normalizedUrl).digest('hex');

    // Check if report already exists for this URL
    let report = await ThreatReportModel.findOne({ urlHash });
    if (report) {
      report.reportCount += 1;
      await report.save();
      return reply.status(200).send({
        report,
        message: 'Existing community threat report incremented.',
      });
    }

    report = await ThreatReportModel.create({
      submittedUrl: normalizedUrl,
      normalizedDomain,
      urlHash,
      category,
      description,
      status: ThreatReportStatusEnum.SUBMITTED,
      reportCount: 1,
      submitterEmail,
    });

    return reply.status(201).send({
      report,
      message: 'Threat report submitted successfully for community verification.',
    });
  });

  // GET /api/v1/community/reports - List community threat reports with vote counts
  app.get('/reports', async (request, reply) => {
    const voterId = deriveVoterIdentity(request.ip);

    const reports = await ThreatReportModel.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const reportIds = reports.map((r: any) => r._id);

    // Aggregate votes per report
    const votesAgg = await ThreatVoteModel.aggregate([
      { $match: { reportId: { $in: reportIds } } },
      {
        $group: {
          _id: { reportId: '$reportId', vote: '$vote' },
          count: { $sum: 1 },
        },
      },
    ]);

    const voteMap = new Map<string, { upvotes: number; downvotes: number }>();
    for (const v of votesAgg) {
      const repIdStr = String(v._id.reportId);
      if (!voteMap.has(repIdStr)) {
        voteMap.set(repIdStr, { upvotes: 0, downvotes: 0 });
      }
      const entry = voteMap.get(repIdStr)!;
      if (v._id.vote === VoteTypeEnum.UPVOTE) {
        entry.upvotes = v.count;
      } else if (v._id.vote === VoteTypeEnum.DOWNVOTE) {
        entry.downvotes = v.count;
      }
    }

    // User's own votes derived from server-controlled voter identity
    const userVotes = await ThreatVoteModel.find({
      reportId: { $in: reportIds },
      userId: voterId,
    }).lean();
    const userVoteMap = new Map(userVotes.map((uv: any) => [String(uv.reportId), uv.vote]));

    const reportsWithVotes = reports.map((r: any) => {
      const repIdStr = String(r._id);
      const votes = voteMap.get(repIdStr) || { upvotes: 0, downvotes: 0 };
      return {
        ...r,
        upvotes: votes.upvotes,
        downvotes: votes.downvotes,
        userVote: userVoteMap.get(repIdStr) || null,
      };
    });

    return reply.send({ reports: reportsWithVotes });
  });

  // POST /api/v1/community/reports/:id/vote - Cast vote on community threat report
  app.post(
    '/reports/:id/vote',
    {
      config: {
        rateLimit: {
          max: 20,
          timeWindow: '1 minute',
          errorResponseBuilder: () => ({
            statusCode: 429,
            error: 'RATE_LIMIT_EXCEEDED',
            message: 'Community voting rate limit exceeded. Please wait before submitting additional votes.',
          }),
        },
      },
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Invalid threat report ID format',
        });
      }

      const parseResult = ThreatVoteCreateSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Invalid vote parameters',
          details: parseResult.error.issues,
        });
      }

      const { vote } = parseResult.data;

      // SECURITY: Server-controlled voter identity derived from client IP.
      // Arbitrary client-provided session identifiers are disregarded to enforce 1 vote per report per source IP.
      const userId = deriveVoterIdentity(request.ip);

      const report = await ThreatReportModel.findById(id);
      if (!report) {
        return reply.status(404).send({ error: 'NOT_FOUND', message: 'Report not found' });
      }

      const threatVote = await ThreatVoteModel.findOneAndUpdate(
        { reportId: report._id, userId },
        { reportId: report._id, userId, vote },
        { upsert: true, new: true }
      );

      return reply.send({
        message: 'Vote recorded',
        vote: threatVote.vote,
      });
    }
  );
};
