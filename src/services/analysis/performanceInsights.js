const logger = require('../../config/logger');

const { PerformanceInsightType } = require('../../models/enums');

/**
 * Analyze performance insights and snapshot
 * @param {Array} trades
 * @param {Object} plan
 * @param {string} period
 * @returns {Object}
 */
const analyzePerformanceInsights = (trades, plan, period) => {
  logger.info('Analysis: Starting performance insights analysis');
  if (trades.length === 0 || !plan) {
    return {
      period,
      insights: [
        {
          type: PerformanceInsightType.CONSTRUCTIVE,
          title: 'Add data to unlock insights',
          description: 'Record trades and set a plan to generate meaningful feedback',
          metric: { label: 'Trades analyzed', value: 0 },
        },
      ],
      stats: { winRate: 0, avgRiskReward: 0, planAdherence: 0, tradesThisWeek: 0 },
      recommendations: ['Start with a small set of trades (5-10) to calibrate'],
    };
  }

  const totalTrades = trades.length;
  const wins = trades.filter((t) => t.profitLoss > 0).length;
  const winRate = totalTrades > 0 ? Math.round((wins / totalTrades) * 100) : 0;

  // Calculate avgRR only from trades with non-null riskRewardAchieved
  const tradesWithRR = trades.filter((t) => t.riskRewardAchieved != null);
  const avgRR =
    tradesWithRR.length > 0
      ? Math.round((tradesWithRR.reduce((s, t) => s + t.riskRewardAchieved, 0) / tradesWithRR.length) * 100) / 100
      : 0;

  // Calculate plan adherence for period - only count breaches from trades with non-null riskPercentUsed
  const riskBreachesRatio =
    trades.filter((t) => t.riskPercentUsed != null && t.riskPercentUsed > (plan.riskPercentPerTrade || 0) * 1.5).length /
    totalTrades;
  const outsideSessionRatio = trades.filter((t) => !(plan.preferredSessions || []).includes(t.session)).length / totalTrades;
  const planAdherence = Math.round(((1 - riskBreachesRatio + (1 - outsideSessionRatio)) / 2) * 100);

  // Weekly trade count
  const now = new Date();
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - 7);
  const tradesThisWeek = trades.filter((t) => new Date(t.entryTime) >= startOfWeek).length;

  const insights = [];

  // Positive reinforcement
  if (planAdherence >= 70) {
    insights.push({
      type: PerformanceInsightType.POSITIVE,
      title: 'Strong plan adherence',
      description: 'You are trading within your rules. Keep it up.',
      metric: { label: 'Plan adherence', value: `${planAdherence}%` },
    });
  } else if (winRate >= 60) {
    insights.push({
      type: PerformanceInsightType.POSITIVE,
      title: 'Solid win rate',
      description: 'Your recent outcomes are favorable without overtrading.',
      metric: { label: 'Win rate', value: `${winRate}%` },
    });
  }

  // Constructive feedback - only count early exits from trades with non-null targetPercentAchieved
  const earlyExits = trades.filter(
    (t) => t.exitedEarly || (t.targetPercentAchieved != null && t.targetPercentAchieved < 50)
  ).length;
  if (earlyExits / totalTrades >= 0.3) {
    insights.push({
      type: PerformanceInsightType.CONSTRUCTIVE,
      title: 'Exiting too early',
      description: 'Consider scaling out or letting winners reach planned targets.',
      metric: { label: 'Early exits', value: `${Math.round((earlyExits / totalTrades) * 100)}%` },
    });
  } else if (planAdherence < 60) {
    insights.push({
      type: PerformanceInsightType.CONSTRUCTIVE,
      title: 'Improve plan adherence',
      description: 'Stick to sessions and daily trade limits before optimizing entries.',
      metric: { label: 'Plan adherence', value: `${planAdherence}%` },
    });
  }

  // Ensure at least one positive and one constructive
  if (!insights.some((i) => i.type === PerformanceInsightType.POSITIVE)) {
    insights.push({
      type: PerformanceInsightType.POSITIVE,
      title: 'Consistent practice',
      description: 'Consistency builds edge. Keep logging trades and reviewing.',
      metric: { label: 'Trades analyzed', value: totalTrades },
    });
  }
  if (!insights.some((i) => i.type === PerformanceInsightType.CONSTRUCTIVE)) {
    insights.push({
      type: PerformanceInsightType.CONSTRUCTIVE,
      title: 'Refine exits',
      description: 'Define rules for taking profits to reduce second-guessing.',
      metric: { label: 'Avg R:R', value: avgRR },
    });
  }

  return {
    period,
    insights,
    stats: { winRate, avgRiskReward: avgRR, planAdherence, tradesThisWeek },
    recommendations: insights.filter((i) => i.type === PerformanceInsightType.CONSTRUCTIVE).map((i) => i.description),
  };
};

module.exports = analyzePerformanceInsights;
