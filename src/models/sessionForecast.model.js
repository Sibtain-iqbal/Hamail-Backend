const mongoose = require('mongoose');
const { toJSON } = require('./plugins');
const { TradingSessions, PsychologicalState, RiskLevel } = require('./enums');

const sessionForecastSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    session: {
      type: String,
      enum: Object.values(TradingSessions),
      required: true,
      index: true,
    },
    predictedBias: {
      type: String,
      required: true,
      trim: true,
    },
    riskLevel: {
      type: String,
      enum: Object.values(RiskLevel),
      required: true,
      index: true,
    },
    recommendations: {
      type: [String],
      required: true,
      default: [],
    },
    basedOnState: {
      type: String,
      enum: Object.values(PsychologicalState),
      required: true,
      index: true,
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
sessionForecastSchema.index({ userId: 1, timestamp: -1 });
sessionForecastSchema.index({ session: 1, timestamp: -1 });

sessionForecastSchema.plugin(toJSON);

const SessionForecast = mongoose.model('SessionForecast', sessionForecastSchema);

module.exports = SessionForecast;
