import mongoose, { Schema, Document } from 'mongoose';
import {
  IndicatorTypeEnum,
  FindingSeverityEnum,
  type IndicatorType,
  type FindingSeverity,
} from '@sentrix/shared';

export interface IThreatIndicatorDocument extends Document {
  type: IndicatorType;
  value: string;
  normalizedValue: string;
  severity: FindingSeverity;
  firstSeen: Date;
  lastSeen: Date;
  occurrences: number;
  relatedScanIds: mongoose.Types.ObjectId[];
  relatedMessageIds: mongoose.Types.ObjectId[];
  relatedReportIds: mongoose.Types.ObjectId[];
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
}

const ThreatIndicatorSchema = new Schema<IThreatIndicatorDocument>(
  {
    type: {
      type: String,
      enum: Object.values(IndicatorTypeEnum),
      required: true,
      index: true,
    },
    value: {
      type: String,
      required: true,
      trim: true,
    },
    normalizedValue: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true,
    },
    severity: {
      type: String,
      enum: Object.values(FindingSeverityEnum),
      default: FindingSeverityEnum.INFO,
      index: true,
    },
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
      index: true,
    },
    occurrences: {
      type: Number,
      default: 1,
      min: 1,
    },
    relatedScanIds: [
      {
        type: Schema.Types.ObjectId,
        ref: 'Scan',
      },
    ],
    relatedMessageIds: [
      {
        type: Schema.Types.ObjectId,
        ref: 'MessageAnalysis',
      },
    ],
    relatedReportIds: [
      {
        type: Schema.Types.ObjectId,
        ref: 'ThreatReport',
      },
    ],
    tags: [{ type: String }],
  },
  {
    timestamps: true,
    autoIndex: false,
  }
);

ThreatIndicatorSchema.index({ type: 1, normalizedValue: 1 }, { unique: true });
ThreatIndicatorSchema.index({ occurrences: -1 });

export const ThreatIndicatorModel =
  mongoose.models.ThreatIndicator ||
  mongoose.model<IThreatIndicatorDocument>('ThreatIndicator', ThreatIndicatorSchema);
