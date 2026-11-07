import mongoose, { Schema, Document, Types } from 'mongoose';

export interface ICertificateDocument extends Document {
  scanId: Types.ObjectId;
  leaseToken?: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validUntil: string;
  fingerprint: string;
  hostnameMatched: boolean;
  keyAlgorithm?: string;
  keySize?: number;
  signatureAlgorithm?: string;
  hasSCTs?: boolean;
  validityDays?: number;
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
      index: true,
    },
    leaseToken: {
      type: String,
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
    keyAlgorithm: {
      type: String,
    },
    keySize: {
      type: Number,
    },
    signatureAlgorithm: {
      type: String,
    },
    hasSCTs: {
      type: Boolean,
    },
    validityDays: {
      type: Number,
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

CertificateSchema.index({ scanId: 1, leaseToken: 1 }, { unique: true, sparse: true });

export const CertificateModel =
  mongoose.models.Certificate || mongoose.model<ICertificateDocument>('Certificate', CertificateSchema);
