const mongoose = require('mongoose');
const Trade = require('../../src/models/trade.model');

const tradeOne = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  entryTime: new Date('2023-01-01T09:00:00Z'),
  exitTime: new Date('2023-01-01T10:30:00Z'),
  riskPercentUsed: 2.0,
  profitLoss: 150.0,
  riskRewardAchieved: 1.5,
  session: 'LONDON',
  stopLossHit: false,
  exitedEarly: false,
  targetPercentAchieved: 100.0,
  notes: 'Good trade setup',
};

const tradeTwo = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  entryTime: new Date('2023-01-02T14:00:00Z'),
  exitTime: new Date('2023-01-02T15:45:00Z'),
  riskPercentUsed: 1.5,
  profitLoss: -75.0,
  riskRewardAchieved: 0.0,
  session: 'NY',
  stopLossHit: true,
  exitedEarly: false,
  targetPercentAchieved: 0.0,
  notes: 'Stop loss hit',
};

const tradeThree = {
  _id: mongoose.Types.ObjectId(),
  userId: mongoose.Types.ObjectId(),
  entryTime: new Date('2023-01-03T02:00:00Z'),
  exitTime: new Date('2023-01-03T03:15:00Z'),
  riskPercentUsed: 3.0,
  profitLoss: 300.0,
  riskRewardAchieved: 2.0,
  session: 'ASIA',
  stopLossHit: false,
  exitedEarly: true,
  targetPercentAchieved: 200.0,
  notes: 'Exited early with profit',
};

const insertTrades = async (trades) => {
  await Trade.insertMany(trades);
};

module.exports = {
  tradeOne,
  tradeTwo,
  tradeThree,
  insertTrades,
};
