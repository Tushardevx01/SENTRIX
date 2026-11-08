import mongoose, { Schema, Document } from 'mongoose';
import {
  VerdictEnum,
  MessageChannelEnum,
  type Verdict,
  type MessageChannel,
  type ISocialEngineeringFinding,
  type IExtractedIndicators,
  type IThreatIntelMatch,
  type IAIExplanation,
} from '@sentrix/shared';

export interface IMessageAnalysisDocument extends Document {
  messageHash: string;
  channel: MessageChannel;
  senderInfo?: string;
  preview: string;
  messageText: string;
  classification: Verdict;
  riskScore: number;
  confidence: number;
  detectedPatterns: ISocialEngineeringFinding[];
  extractedIndicators: IExtractedIndicators;
  threatIntelMatches: IThreatIntelMatch[];
  aiExplanation: IAIExplanation;
  userIpHash?: string;
  createdAt: Date;
  updatedAt: Date;
}

const MessageAnalysisSchema = new Schema<IMessageAnalysisDocument>(
  {
    messageHash: {
      type: String,
      required: true,
      index: true,
    },
    channel: {
      type: String,
      enum: Object.values(MessageChannelEnum),
      default: MessageChannelEnum.OTHER,
      index: true,
    },
    senderInfo: {
      type: String,
      trim: true,
      maxlength: 256,
    },
    preview: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    messageText: {
      type: String,
      required: true,
      maxlength: 50000,
    },
    classification: {
      type: String,
      enum: Object.values(VerdictEnum),
      required: true,
      index: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    detectedPatterns: [
      {
        tactic: { type: String, required: true },
        severity: { type: String, required: true },
        title: { type: String, required: true },
        description: { type: String, required: true },
        matchedPatterns: [{ type: String }],
      },
    ],
    extractedIndicators: {
      urls: [{ type: String }],
      domains: [{ type: String }],
      emails: [{ type: String }],
      phones: [{ type: String }],
      wallets: [
        {
          address: { type: String, required: true },
          network: { type: String, required: true },
        },
      ],
      paymentRefs: [{ type: String }],
      entities: [{ type: String }],
    },
    threatIntelMatches: [
      {
        indicatorType: { type: String, required: true },
        indicatorValue: { type: String, required: true },
        matchSource: { type: String, required: true },
        severity: { type: String, required: true },
        details: { type: String, required: true },
      },
    ],
    aiExplanation: {
      summary: { type: String, required: true },
      reasoning: [{ type: String }],
      precautions: [{ type: String }],
      limitations: [{ type: String }],
    },
    userIpHash: {
      type: String,
      index: true,
    },
  },
  {
    timestamps: true,
    autoIndex: false,
  }
);

MessageAnalysisSchema.index({ createdAt: -1 });
MessageAnalysisSchema.index({ classification: 1, createdAt: -1 });

export const MessageAnalysisModel =
  mongoose.models.MessageAnalysis ||
  mongoose.model<IMessageAnalysisDocument>('MessageAnalysis', MessageAnalysisSchema);
