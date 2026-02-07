const mongoose = require('mongoose');
const { toJSON } = require('./plugins');
const { PerformanceInsightType } = require('./enums');

const performanceInsightSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: Object.values(PerformanceInsightType),
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
    metric: {
      label: { type: String, trim: true },
      value: { type: mongoose.SchemaTypes.Mixed },
    },
  },
  { _id: false }
);

const performanceSnapshotSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    insights: {
      type: [performanceInsightSchema],
      required: true,
      default: [],
    },
    stats: {
      winRate: { type: Number, required: true, min: 0 },
      avgRiskReward: { type: Number, required: true, min: 0 },
      planAdherence: { type: Number, required: true, min: 0, max: 100 },
      tradesThisWeek: { type: Number, required: true, min: 0 },
    },
    timestamp: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
  },
  { timestamps: true }
);

// Add indexes for better query performance
performanceSnapshotSchema.index({ userId: 1, timestamp: -1 });

performanceSnapshotSchema.plugin(toJSON);

const PerformanceSnapshot = mongoose.model('PerformanceSnapshot', performanceSnapshotSchema);
module.exports = PerformanceSnapshot;
