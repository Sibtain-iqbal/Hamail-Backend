const mongoose = require('mongoose');
const { toJSON } = require('./plugins');
const { PsychologicalState } = require('./enums');

const dashboardSchema = mongoose.Schema(
  {
    userId: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    user: {
      id: {
        type: mongoose.SchemaTypes.ObjectId,
        ref: 'User',
        required: true,
      },
      name: {
        type: String,
        required: true,
        trim: true,
      },
    },
    brainHero: {
      state: {
        type: String,
        enum: Object.values(PsychologicalState),
        required: true,
        index: true,
      },
      stateAnalysis: {
        type: mongoose.SchemaTypes.ObjectId,
        ref: 'StateAnalysis',
        required: true,
      },
    },
    sessionForecast: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'SessionForecast',
      required: true,
    },
    performanceSnapshot: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'PerformanceSnapshot',
      required: true,
    },
    recentTrades: [
      {
        type: mongoose.SchemaTypes.ObjectId,
        ref: 'Trade',
      },
    ],
    tradingPlan: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'TradingPlan',
      required: true,
    },
  },
  { timestamps: true }
);

dashboardSchema.plugin(toJSON);

const Dashboard = mongoose.model('Dashboard', dashboardSchema);

module.exports = Dashboard;
