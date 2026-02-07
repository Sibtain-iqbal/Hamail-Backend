const mongoose = require('mongoose');
const TradingPlan = require('../../src/models/tradingPlan.model');

const tradingPlanOne = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  maxTradesPerDay: 5,
  riskPercentPerTrade: 2.0,
  targetRiskRewardRatio: 1.5,
  preferredSessions: ['LONDON', 'NY'],
  stopLossDiscipline: 'ALWAYS',
};

const tradingPlanTwo = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  maxTradesPerDay: 3,
  riskPercentPerTrade: 1.5,
  targetRiskRewardRatio: 2.0,
  preferredSessions: ['ASIA'],
  stopLossDiscipline: 'FLEXIBLE',
};

const tradingPlanThree = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  maxTradesPerDay: 10,
  riskPercentPerTrade: 3.0,
  targetRiskRewardRatio: 1.0,
  preferredSessions: ['LONDON', 'NY', 'ASIA'],
  stopLossDiscipline: 'ALWAYS',
};

const insertTradingPlans = async (tradingPlans) => {
  await TradingPlan.insertMany(tradingPlans);
};

module.exports = {
  tradingPlanOne,
  tradingPlanTwo,
  tradingPlanThree,
  insertTradingPlans,
};
