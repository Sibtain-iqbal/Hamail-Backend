const mongoose = require('mongoose');
const { toJSON } = require('./plugins');

const windowSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    label: { type: String, required: true },
    score: { type: Number, required: false },
    color: { type: String, required: false },
    tradeCount: { type: Number, required: true, default: 0 },
    metrics: { type: mongoose.SchemaTypes.Mixed, required: false },
    message: { type: String, required: false },
  },
  { _id: false }
);

const insightSchema = new mongoose.Schema(
  {
    type: { type: String, required: false },
    message: { type: String, required: false },
    recommendation: { type: String, required: false },
  },
  { _id: false }
);

const behaviorHeatmapHistorySchema = new mongoose.Schema(
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
    windows: {
      type: [windowSchema],
      required: true,
      default: [],
    },
    insight: {
      type: insightSchema,
      required: false,
    },
    totalTrades: {
      type: Number,
      required: true,
      default: 0,
    },
  },
  { timestamps: true }
);

behaviorHeatmapHistorySchema.index({ userId: 1, date: -1 }, { unique: true });
behaviorHeatmapHistorySchema.plugin(toJSON);

const BehaviorHeatmapHistory = mongoose.model('BehaviorHeatmapHistory', behaviorHeatmapHistorySchema);

module.exports = BehaviorHeatmapHistory;
