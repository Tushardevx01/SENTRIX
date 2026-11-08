import mongoose, { Schema, Document } from 'mongoose';
import { VerdictEnum, type Verdict, type IndicatorType } from '@sentrix/shared';

export interface IThreatCampaignDocument extends Document {
  campaignId: string;
  name: string;
  threatType: string;
  confidence: number;
  indicators: Array<{ type: IndicatorType; value: string }>;
  relatedIncidents: Array<{
    id: string;
    target: string;
    verdict: Verdict;
    type: 'SCAN' | 'MESSAGE' | 'REPORT';
    timestamp: Date;
  }>;
  summary: string;
  createdAt: Date;
  updatedAt: Date;
}

const ThreatCampaignSchema = new Schema<IThreatCampaignDocument>(
  {
    campaignId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    threatType: {
      type: String,
      required: true,
      index: true,
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    indicators: [
      {
        type: { type: String, required: true },
        value: { type: String, required: true },
      },
    ],
    relatedIncidents: [
      {
        id: { type: String, required: true },
        target: { type: String, required: true },
        verdict: { type: String, enum: Object.values(VerdictEnum), required: true },
        type: { type: String, enum: ['SCAN', 'MESSAGE', 'REPORT'], required: true },
        timestamp: { type: Date, default: Date.now },
      },
    ],
    summary: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
    autoIndex: false,
  }
);

ThreatCampaignSchema.index({ updatedAt: -1 });

export const ThreatCampaignModel =
  mongoose.models.ThreatCampaign ||
  mongoose.model<IThreatCampaignDocument>('ThreatCampaign', ThreatCampaignSchema);
