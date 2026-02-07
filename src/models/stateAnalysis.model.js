const mongoose = require('mongoose');
const { toJSON } = require('./plugins');
const { PsychologicalState } = require('./enums');

const stateIndicatorSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      required: true,
      trim: true,
    },
    message: {
      type: String,
      required: true,
      trim: true,
    },
    severity: {
      type: String,
      enum: ['positive', 'neutral', 'warning', 'critical'],
      required: true,
    },
    value: {
      type: Number,
    },
  },
  { _id: false }
);

const stateAnalysisSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    state: {
      type: String,
      enum: Object.values(PsychologicalState),
      required: true,
      index: true,
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    indicators: {
      type: [stateIndicatorSchema],
      required: true,
      default: [],
    },
    analyzedTradeCount: {
      type: Number,
      required: true,
      min: 0,
    },
    dateRange: {
      from: { type: Date, required: true },
      to: { type: Date, required: true },
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
stateAnalysisSchema.index({ userId: 1, timestamp: -1 });
stateAnalysisSchema.index({ state: 1, timestamp: -1 });

stateAnalysisSchema.plugin(toJSON);

const StateAnalysis = mongoose.model('StateAnalysis', stateAnalysisSchema);

module.exports = StateAnalysis;
