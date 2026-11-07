import mongoose, { Schema, Document, Types } from 'mongoose';
import { VoteTypeEnum, type VoteType } from '@sentrix/shared';

export interface IThreatVoteDocument extends Document {
  reportId: Types.ObjectId;
  userId: string;
  vote: VoteType;
  createdAt: Date;
  updatedAt: Date;
}

const ThreatVoteSchema = new Schema<IThreatVoteDocument>(
  {
    reportId: {
      type: Schema.Types.ObjectId,
      ref: 'ThreatReport',
      required: true,
      index: true,
    },
    userId: {
      type: String,
      required: true,
      index: true,
    },
    vote: {
      type: String,
      enum: Object.values(VoteTypeEnum),
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Prevent duplicate voting per user/session for the same report
ThreatVoteSchema.index({ reportId: 1, userId: 1 }, { unique: true });

export const ThreatVoteModel =
  mongoose.models.ThreatVote || mongoose.model<IThreatVoteDocument>('ThreatVote', ThreatVoteSchema);
