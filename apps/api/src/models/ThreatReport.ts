import mongoose, { Schema, Document } from 'mongoose';
import {
  ThreatCategoryEnum,
  ThreatReportStatusEnum,
  type ThreatCategory,
  type ThreatReportStatus,
} from '@sentrix/shared';

export interface IThreatReportDocument extends Document {
  submittedUrl: string;
  normalizedDomain: string;
  urlHash: string;
  category: ThreatCategory;
  description: string;
  status: ThreatReportStatus;
  reportCount: number;
  submitterEmail?: string;
  createdAt: Date;
  updatedAt: Date;
}

const ThreatReportSchema = new Schema<IThreatReportDocument>(
  {
    submittedUrl: {
      type: String,
      required: true,
      trim: true,
    },
    normalizedDomain: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    urlHash: {
      type: String,
      required: true,
      index: true,
    },
    category: {
      type: String,
      enum: Object.values(ThreatCategoryEnum),
      required: true,
      index: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    status: {
      type: String,
      enum: Object.values(ThreatReportStatusEnum),
      default: ThreatReportStatusEnum.SUBMITTED,
      index: true,
    },
    reportCount: {
      type: Number,
      default: 1,
      min: 1,
    },
    submitterEmail: {
      type: String,
      lowercase: true,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

ThreatReportSchema.index({ createdAt: -1 });

export const ThreatReportModel =
  mongoose.models.ThreatReport ||
  mongoose.model<IThreatReportDocument>('ThreatReport', ThreatReportSchema);
