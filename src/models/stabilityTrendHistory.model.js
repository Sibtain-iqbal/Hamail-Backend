const mongoose = require('mongoose');
const { toJSON } = require('./plugins');

const metricsSchema = new mongoose.Schema(
  {
    avgPlanCompliance: { type: Number, required: true },
    behavioralVolatility: { type: Number, required: true },
    riskConsistency: { type: Number, required: true },
    emotionalTradeFrequency: { type: Number, required: true },
    batteryStability: { type: Number, required: true },
  },
  { _id: false }
);

const stabilityTrendHistorySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    date: {
      type: Date,
      required: true,
      index: true,
    },
    score: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    metrics: {
      type: metricsSchema,
      required: true,
    },
  },
  { timestamps: true }
);

stabilityTrendHistorySchema.index({ userId: 1, date: -1 }, { unique: true });
stabilityTrendHistorySchema.plugin(toJSON);

const StabilityTrendHistory = mongoose.model('StabilityTrendHistory', stabilityTrendHistorySchema);

module.exports = StabilityTrendHistory;
