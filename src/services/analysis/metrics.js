const computeMedian = require('../../utils/computeMedian');

/**
 * Calculate basic trade metrics
 * @param {Array} trades
 * @returns {Object}
 */
const calculateBasicMetrics = (trades) => {
  const totalTrades = trades.length;
  if (totalTrades === 0) {
    return {
      winRate: 0,
      avgRiskUsed: 0,
      avgRR: 0,
      medianTargetPct: 0,
      nearTargetHits: 0,
      earlyExits: 0,
      riskBreaches: 0,
    };
  }

  const winCount = trades.filter((t) => t.profitLoss > 0).length;
  const winRate = winCount / totalTrades;

  // Calculate avgRiskUsed only from trades with non-null riskPercentUsed
  const tradesWithRisk = trades.filter((t) => t.riskPercentUsed != null);
  const avgRiskUsed =
    tradesWithRisk.length > 0 ? tradesWithRisk.reduce((sum, t) => sum + t.riskPercentUsed, 0) / tradesWithRisk.length : 0;

  // Calculate avgRR only from trades with non-null riskRewardAchieved
  const tradesWithRR = trades.filter((t) => t.riskRewardAchieved != null);
  const avgRR =
    tradesWithRR.length > 0 ? tradesWithRR.reduce((sum, t) => sum + t.riskRewardAchieved, 0) / tradesWithRR.length : 0;

  const targetPercents = trades.map((t) => t.targetPercentAchieved).filter((v) => typeof v === 'number' && v != null);
  const sortedTargetPercents = targetPercents.slice().sort((a, b) => a - b);
  const medianTargetPct = computeMedian(sortedTargetPercents);
  const nearTargetHits = trades.filter((t) => t.targetPercentAchieved != null && t.targetPercentAchieved >= 80).length;

  const earlyExits = trades.filter((t) => {
    const pct = t.targetPercentAchieved;
    const profitableEarly = t.profitLoss > 0 && pct != null && pct >= 30 && pct <= 80;
    return t.exitedEarly === true || profitableEarly;
  }).length;

  return {
    winRate,
    avgRiskUsed,
    avgRR,
    medianTargetPct,
    nearTargetHits,
    earlyExits,
  };
};

/**
 * Calculate day-based metrics
 * @param {Array} trades
 * @param {Object} plan
 * @returns {Object}
 */
const calculateDayMetrics = (trades, plan) => {
  const tradesByDay = {};
  const outsideSessionByDay = {};

  trades.forEach((t) => {
    const dayKey = new Date(t.entryTime).toISOString().split('T')[0];
    tradesByDay[dayKey] = (tradesByDay[dayKey] || 0) + 1;
    const isOutside = !(plan.preferredSessions || []).includes(t.session);
    if (isOutside) {
      outsideSessionByDay[dayKey] = true;
    }
  });

  const daysWithTrades = Object.keys(tradesByDay).length || 1;
  const exceededDays = Object.values(tradesByDay).filter((cnt) => cnt > (plan.maxTradesPerDay || Infinity)).length;
  const outsideSessionDays = Object.keys(outsideSessionByDay).length;

  return {
    daysWithTrades,
    exceededDays,
    outsideSessionDays,
  };
};

/**
 * Calculate risk spike detection
 * @param {Array} trades
 * @param {number} planRisk
 * @returns {Object}
 */
const calculateRiskSpike = (trades, planRisk) => {
  const totalTrades = trades.length;
  if (totalTrades === 0) {
    return { riskSpike: false, last3Breaches: 0 };
  }

  // Calculate recentAvgRisk only from trades with non-null riskPercentUsed
  const tradesWithRisk = trades.filter((t) => t.riskPercentUsed != null);
  const recentAvgRisk =
    tradesWithRisk.length > 0 ? tradesWithRisk.reduce((s, t) => s + t.riskPercentUsed, 0) / tradesWithRisk.length : planRisk;
  const last3 = trades.slice(0, 3);
  const riskSpikeThreshold = Math.max(planRisk * 1.3, recentAvgRisk * 1.3);
  const last3Breaches = last3.filter((t) => t.riskPercentUsed != null && t.riskPercentUsed > riskSpikeThreshold).length;
  const riskSpike = last3Breaches >= 2;

  return { riskSpike, last3Breaches };
};

/**
 * Calculate risk breaches
 * @param {Array} trades
 * @param {number} planRisk
 * @returns {number}
 */
const calculateRiskBreaches = (trades, planRisk) => {
  return trades.filter((t) => t.riskPercentUsed != null && t.riskPercentUsed > planRisk * 1.5).length;
};

module.exports = {
  calculateBasicMetrics,
  calculateDayMetrics,
  calculateRiskSpike,
  calculateRiskBreaches,
};
