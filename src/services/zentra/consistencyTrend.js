const logger = require('../../config/logger');
const { calculatePlanControl } = require('./planControl');
const { calculatePsychologicalRadar } = require('./psychologicalRadar');

/**
 * Group trades by calendar day
 */
const groupTradesByDay = (trades) => {
  const grouped = {};

  trades.forEach((trade) => {
    const date = new Date(trade.entryTime);
    const dayKey = date.toISOString().split('T')[0]; // YYYY-MM-DD

    if (!grouped[dayKey]) {
      grouped[dayKey] = [];
    }
    grouped[dayKey].push(trade);
  });

  return grouped;
};

/**
 * Calculate risk consistency (100 - risk variability %)
 */
const calculateRiskConsistency = (trades, planRisk) => {
  if (trades.length === 0 || !planRisk) return 100;

  const risksUsed = trades.filter((t) => t.riskPercentUsed).map((t) => t.riskPercentUsed);
  if (risksUsed.length === 0) return 100;

  const avgRisk = risksUsed.reduce((a, b) => a + b, 0) / risksUsed.length;
  const variance = risksUsed.reduce((sum, val) => sum + Math.pow(val - avgRisk, 2), 0) / risksUsed.length;
  const stdDev = Math.sqrt(variance);

  const variability = avgRisk > 0 ? (stdDev / avgRisk) * 100 : 0;
  return Math.max(0, Math.min(100, 100 - variability));
};

/**
 * Calculate emotional trade frequency (impulsive/revenge trades / total * 100)
 */
const calculateEmotionalTradeFrequency = (trades, planRisk) => {
  if (trades.length === 0) return 0;

  let emotionalCount = 0;
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 0; i < sortedTrades.length; i++) {
    // Check impulsive (re-entry < 30 mins)
    let isImpulsive = false;
    if (i > 0) {
      const prevExit = new Date(sortedTrades[i - 1].exitTime);
      const currEntry = new Date(sortedTrades[i].entryTime);
      const diffMinutes = (currEntry - prevExit) / (1000 * 60);
      if (diffMinutes < 30 && diffMinutes >= 0) {
        emotionalCount++;
        isImpulsive = true;
      }
    }

    // Check revenge trade (loss followed by oversized)
    if (!isImpulsive && i > 0 && sortedTrades[i - 1].profitLoss < 0) {
      if (sortedTrades[i].riskPercentUsed && sortedTrades[i].riskPercentUsed > planRisk * 1.3) {
        emotionalCount++;
      }
    }
  }

  return (emotionalCount / trades.length) * 100;
};

/**
 * Calculate battery stability (inverse of battery change)
 * Less change = better stability
 * Simplified: estimate based on trade behavior
 */
const calculateBatteryStability = (trades, planRisk) => {
  if (trades.length === 0) return 100;

  // Count negative behaviors that would drain battery
  let drainEvents = 0;
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 0; i < sortedTrades.length; i++) {
    // Impulsive re-entry
    if (i > 0) {
      const prevExit = new Date(sortedTrades[i - 1].exitTime);
      const currEntry = new Date(sortedTrades[i].entryTime);
      const diffMinutes = (currEntry - prevExit) / (1000 * 60);
      if (diffMinutes < 30 && diffMinutes >= 0) drainEvents++;
    }

    // Oversized trade
    if (sortedTrades[i].riskPercentUsed && sortedTrades[i].riskPercentUsed > planRisk * 1.3) {
      drainEvents++;
    }

    // Large loss
    if (sortedTrades[i].profitLoss < -2 * planRisk) {
      drainEvents++;
    }
  }

  // Max drain events = trades.length * 3 (theoretical max)
  const maxDrainEvents = trades.length * 2;
  const stability = 100 - (drainEvents / maxDrainEvents) * 100;

  return Math.max(0, Math.min(100, stability));
};

/**
 * Calculate daily psychological score
 * Formula:
 * avgPlanCompliance * 0.35 +
 * (100 - behavioralVolatility) * 0.25 +
 * riskConsistency * 0.20 +
 * (100 - emotionalTradeFrequency) * 0.15 +
 * batteryStability * 0.05
 */
const calculateDailyScore = (trades, plan) => {
  if (trades.length === 0) return null;

  const planRisk = plan?.riskPercentPerTrade || 1;

  // Average plan compliance
  const { percentage: avgPlanCompliance } = calculatePlanControl(trades, plan);

  // Behavioral volatility from radar
  const { traits } = calculatePsychologicalRadar(trades, plan);
  const behavioralVolatility = traits.emotionalVolatility;

  // Risk consistency
  const riskConsistency = calculateRiskConsistency(trades, planRisk);

  // Emotional trade frequency
  const emotionalTradeFrequency = calculateEmotionalTradeFrequency(trades, planRisk);

  // Battery stability
  const batteryStability = calculateBatteryStability(trades, planRisk);

  // Calculate final score
  const score =
    avgPlanCompliance * 0.35 +
    (100 - behavioralVolatility) * 0.25 +
    riskConsistency * 0.2 +
    (100 - emotionalTradeFrequency) * 0.15 +
    batteryStability * 0.05;

  return {
    score: Math.round(Math.max(0, Math.min(100, score))),
    metrics: {
      avgPlanCompliance: Math.round(avgPlanCompliance),
      behavioralVolatility: Math.round(behavioralVolatility),
      riskConsistency: Math.round(riskConsistency),
      emotionalTradeFrequency: Math.round(emotionalTradeFrequency),
      batteryStability: Math.round(batteryStability),
    },
    tradeCount: trades.length,
  };
};

/**
 * Calculate consistency trend over specified days
 * @param {Array} trades - All trades within date range
 * @param {Object} plan - Trading plan
 * @param {string} daysOption - '7', '10', '20', or 'all'
 * @returns {Object} Trend data
 */
const calculateConsistencyTrend = (trades, plan, daysOption = '7') => {
  logger.info('[ConsistencyTrend] Calculating for %d trades, days: %s', trades.length, daysOption);

  if (!trades || trades.length === 0) {
    return {
      trend: [],
      summary: {
        averageScore: 0,
        trendDirection: 'stable',
        daysWithData: 0,
        totalDays: 0,
      },
    };
  }

  // Determine date range
  const now = new Date();
  let startDate;

  if (daysOption === 'all') {
    // Find earliest trade
    const earliest = trades.reduce((min, t) => (new Date(t.entryTime) < min ? new Date(t.entryTime) : min), new Date());
    startDate = earliest;
  } else {
    const days = parseInt(daysOption, 10);
    startDate = new Date(now);
    startDate.setDate(startDate.getDate() - days);
  }

  // Filter trades within range
  const filteredTrades = trades.filter((t) => new Date(t.entryTime) >= startDate);

  // Group by day
  const groupedTrades = groupTradesByDay(filteredTrades);

  // Calculate daily scores
  const trend = [];
  const sortedDays = Object.keys(groupedTrades).sort();

  sortedDays.forEach((day) => {
    const dayTrades = groupedTrades[day];
    const dailyData = calculateDailyScore(dayTrades, plan);

    if (dailyData) {
      trend.push({
        date: day,
        score: dailyData.score,
        metrics: dailyData.metrics,
        tradeCount: dailyData.tradeCount,
      });
    }
  });

  // Calculate summary
  const scores = trend.map((t) => t.score);
  const averageScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

  // Determine trend direction
  let trendDirection = 'stable';
  if (scores.length >= 3) {
    const firstHalf = scores.slice(0, Math.floor(scores.length / 2));
    const secondHalf = scores.slice(Math.floor(scores.length / 2));
    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    if (secondAvg - firstAvg > 5) {
      trendDirection = 'improving';
    } else if (firstAvg - secondAvg > 5) {
      trendDirection = 'deteriorating';
    }
  }

  logger.info(
    '[ConsistencyTrend] Generated %d data points, avg: %d, direction: %s',
    trend.length,
    averageScore,
    trendDirection
  );

  return {
    trend,
    summary: {
      averageScore,
      trendDirection,
      daysWithData: trend.length,
      totalDays: daysOption === 'all' ? trend.length : parseInt(daysOption, 10),
      message: getTrendMessage(trendDirection, averageScore),
    },
  };
};

const getTrendMessage = (direction, avgScore) => {
  if (direction === 'improving') {
    return 'Your psychological consistency is improving';
  } else if (direction === 'deteriorating') {
    return 'Your psychological consistency is declining - review recent behavior';
  } else if (avgScore >= 70) {
    return 'Stable and disciplined trading pattern';
  } else {
    return 'Consistency is stable but has room for improvement';
  }
};

module.exports = {
  calculateConsistencyTrend,
  calculateDailyScore,
  groupTradesByDay,
  calculateRiskConsistency,
  calculateEmotionalTradeFrequency,
  calculateBatteryStability,
};
