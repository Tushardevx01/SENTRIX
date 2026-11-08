import mongoose, { Schema, Document } from 'mongoose';
import {
  BlockchainRecordStatusEnum,
  type BlockchainRecordStatus,
} from '@sentrix/shared';

export interface IBlockchainRecordDocument extends Document {
  reportId: string;
  reportType: 'SCAN' | 'MESSAGE' | 'THREAT_REPORT';
  target: string;
  reportHash: string; // 0x-prefixed 32-byte hex hash
  canonicalData: Record<string, unknown>;
  txHash: string;
  blockNumber: number;
  blockTimestamp: number;
  contractAddress: string;
  chainId: number;
  networkName: string;
  reporterAddress: string;
  status: BlockchainRecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

const BlockchainRecordSchema = new Schema<IBlockchainRecordDocument>(
  {
    reportId: {
      type: String,
      required: true,
      index: true,
    },
    reportType: {
      type: String,
      enum: ['SCAN', 'MESSAGE', 'THREAT_REPORT'],
      required: true,
      index: true,
    },
    target: {
      type: String,
      required: true,
      trim: true,
    },
    reportHash: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    canonicalData: {
      type: Schema.Types.Mixed,
      required: true,
    },
    txHash: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    blockNumber: {
      type: Number,
      required: true,
      index: true,
    },
    blockTimestamp: {
      type: Number,
      required: true,
    },
    contractAddress: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    chainId: {
      type: Number,
      required: true,
    },
    networkName: {
      type: String,
      required: true,
    },
    reporterAddress: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    status: {
      type: String,
      enum: Object.values(BlockchainRecordStatusEnum),
      default: BlockchainRecordStatusEnum.CONFIRMED,
      index: true,
    },
  },
  {
    timestamps: true,
    autoIndex: false,
  }
);

BlockchainRecordSchema.index({ createdAt: -1 });

export const BlockchainRecordModel =
  mongoose.models.BlockchainRecord ||
  mongoose.model<IBlockchainRecordDocument>('BlockchainRecord', BlockchainRecordSchema);
