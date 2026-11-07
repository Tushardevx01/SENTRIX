import mongoose, { Schema, Document, Types } from 'mongoose';
import {
  FindingCategoryEnum,
  FindingSeverityEnum,
  type FindingCategory,
  type FindingSeverity,
} from '@sentrix/shared';

export interface IFindingDocument extends Document {
  scanId: Types.ObjectId;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  confidence: number;
  createdAt: Date;
  updatedAt: Date;
}

const FindingSchema = new Schema<IFindingDocument>(
  {
    scanId: {
      type: Schema.Types.ObjectId,
      ref: 'Scan',
      required: true,
      index: true,
    },
    category: {
      type: String,
      enum: Object.values(FindingCategoryEnum),
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: Object.values(FindingSeverityEnum),
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    evidence: {
      type: Schema.Types.Mixed,
      default: () => ({}),
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
  },
  {
    timestamps: true,
  }
);

FindingSchema.index({ scanId: 1, severity: 1 });

export const FindingModel =
  mongoose.models.Finding || mongoose.model<IFindingDocument>('Finding', FindingSchema);
