import mongoose, { Schema, Document, Types } from 'mongoose';

export interface ICertificateDocument extends Document {
  scanId: Types.ObjectId;
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  fingerprint: string;
  hostnameMatched: boolean;
  rawDetails?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

const CertificateSchema = new Schema<ICertificateDocument>(
  {
    scanId: {
      type: Schema.Types.ObjectId,
      ref: 'Scan',
      required: true,
      unique: true,
      index: true,
    },
    issuer: {
      type: String,
      required: true,
      trim: true,
    },
    subject: {
      type: String,
      required: true,
      trim: true,
    },
    validFrom: {
      type: String,
      required: true,
    },
    validUntil: {
      type: String,
      required: true,
    },
    fingerprint: {
      type: String,
      required: true,
      index: true,
    },
    hostnameMatched: {
      type: Boolean,
      required: true,
    },
    rawDetails: {
      type: Schema.Types.Mixed,
      default: () => ({}),
    },
  },
  {
    timestamps: true,
  }
);

export const CertificateModel =
  mongoose.models.Certificate || mongoose.model<ICertificateDocument>('Certificate', CertificateSchema);
