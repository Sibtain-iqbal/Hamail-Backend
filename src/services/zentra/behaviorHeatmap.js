const logger = require('../../config/logger');
const { calculateTradeScore } = require('./planControl');

/**
 * Time windows for heatmap (24-hour format)
 */
// Full 24h coverage in 3-hour blocks for crypto traders
const TIME_WINDOWS = [
  { id: '00-03', label: '12 AM - 3 AM', startHour: 0, endHour: 3 },
  { id: '03-06', label: '3 AM - 6 AM', startHour: 3, endHour: 6 },
  { id: '06-09', label: '6 AM - 9 AM', startHour: 6, endHour: 9 },
  { id: '09-12', label: '9 AM - 12 PM', startHour: 9, endHour: 12 },
  { id: '12-15', label: '12 PM - 3 PM', startHour: 12, endHour: 15 },
  { id: '15-18', label: '3 PM - 6 PM', startHour: 15, endHour: 18 },
  { id: '18-21', label: '6 PM - 9 PM', startHour: 18, endHour: 21 },
  { id: '21-24', label: '9 PM - 12 AM', startHour: 21, endHour: 24 },
];

/**
 * Get time window for a trade based on entry time
 */
const getTimeWindow = (trade) => {
  const entryHour = new Date(trade.entryTime).getHours();
  return TIME_WINDOWS.find((w) => entryHour >= w.startHour && entryHour < w.endHour);
};

/**
 * Calculate win/loss expectancy (0-100)
 * Formula: (wins - losses) / totalTrades * 50 + 50
 */
const calculateWinLossExpectancy = (trades) => {
  if (trades.length === 0) return 50; // Neutral

  const wins = trades.filter((t) => t.profitLoss > 0).length;
  const losses = trades.filter((t) => t.profitLoss < 0).length;

  const expectancy = ((wins - losses) / trades.length) * 50 + 50;
  return Math.max(0, Math.min(100, expectancy));
};

/**
 * Calculate plan compliance for window trades
 */
const calculateWindowPlanCompliance = (trades, plan) => {
  if (trades.length === 0) return 50;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let totalScore = 0;

  sortedTrades.forEach((trade, index) => {
    const prevTrade = index > 0 ? sortedTrades[index - 1] : null;
    const { score } = calculateTradeScore(trade, plan, prevTrade);
    totalScore += score;
  });

  return Math.round(totalScore / trades.length);
};

/**
 * Calculate impulsiveness penalty (count * 15, cap 100)
 */
const calculateImpulsivenessPenalty = (trades) => {
  if (trades.length < 2) return 0;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let impulsiveCount = 0;

  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffMinutes = (currEntry - prevExit) / (1000 * 60);
    if (diffMinutes < 30 && diffMinutes >= 0) {
      impulsiveCount++;
    }
  }

  return Math.min(impulsiveCount * 15, 100);
};

/**
 * Calculate hesitation penalty (count * 10, cap 100)
 * Hesitation: early exit OR low target achievement (<60%)
 */
const calculateHesitationPenalty = (trades) => {
  if (trades.length === 0) return 0;

  let hesitationCount = 0;
  trades.forEach((trade) => {
    if (trade.exitedEarly) {
      hesitationCount++;
    } else if (trade.targetPercentAchieved && trade.targetPercentAchieved < 60 && trade.profitLoss > 0) {
      hesitationCount++;
    }
  });

  return Math.min(hesitationCount * 10, 100);
};

/**
 * Calculate risk deviation penalty
 * Higher standard deviation = higher penalty
 */
const calculateRiskDeviationPenalty = (trades, planRisk) => {
  if (trades.length === 0 || !planRisk) return 0;

  const risksUsed = trades.filter((t) => t.riskPercentUsed).map((t) => t.riskPercentUsed);
  if (risksUsed.length === 0) return 0;

  const mean = risksUsed.reduce((a, b) => a + b, 0) / risksUsed.length;
  const variance = risksUsed.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / risksUsed.length;
  const stdDev = Math.sqrt(variance);

  // Map stdDev to 0-100 (higher stdDev = higher penalty)
  // Assuming stdDev > planRisk is very bad
  const penalty = Math.min((stdDev / planRisk) * 50, 100);
  return Math.round(penalty);
};

/**
 * Calculate volatility penalty
 * +20 if oversized AND undersized trades occur in same window
 */
const calculateVolatilityPenalty = (trades, planRisk) => {
  if (trades.length < 2 || !planRisk) return 0;

  const hasOversized = trades.some((t) => t.riskPercentUsed && t.riskPercentUsed > planRisk * 1.3);
  const hasUndersized = trades.some((t) => t.riskPercentUsed && t.riskPercentUsed < planRisk * 0.7);

  return hasOversized && hasUndersized ? 20 : 0;
};

/**
 * Calculate frequency penalty
 * If >3 trades: (count - 3) * 5, cap 25
 */
const calculateFrequencyPenalty = (trades) => {
  if (trades.length <= 3) return 0;
  return Math.min((trades.length - 3) * 5, 25);
};

/**
 * Calculate behavior score for a time window
 * Weighted formula:
 * - winLoss * 0.20
 * - planCompliance * 0.30
 * - (100 - impulsiveness) * 0.15
 * - (100 - hesitation) * 0.15
 * - (100 - riskDev) * 0.10
 * - (100 - volatility) * 0.05
 * - (100 - frequency) * 0.05
 */
const calculateWindowScore = (trades, plan) => {
  const planRisk = plan?.riskPercentPerTrade || 1;

  const winLoss = calculateWinLossExpectancy(trades);
  const planCompliance = calculateWindowPlanCompliance(trades, plan);
  const impulsiveness = calculateImpulsivenessPenalty(trades);
  const hesitation = calculateHesitationPenalty(trades);
  const riskDev = calculateRiskDeviationPenalty(trades, planRisk);
  const volatility = calculateVolatilityPenalty(trades, planRisk);
  const frequency = calculateFrequencyPenalty(trades);

  const score =
    winLoss * 0.2 +
    planCompliance * 0.3 +
    (100 - impulsiveness) * 0.15 +
    (100 - hesitation) * 0.15 +
    (100 - riskDev) * 0.1 +
    (100 - volatility) * 0.05 +
    (100 - frequency) * 0.05;

  return {
    score: Math.round(Math.max(0, Math.min(100, score))),
    metrics: {
      winLoss: Math.round(winLoss),
      planCompliance: Math.round(planCompliance),
      impulsiveness: Math.round(impulsiveness),
      hesitation: Math.round(hesitation),
      riskDeviation: Math.round(riskDev),
      volatility: Math.round(volatility),
      frequency: Math.round(frequency),
    },
  };
};

/**
 * Get color status based on score
 */
const getColorStatus = (score) => {
  if (score >= 70) return 'green'; // Disciplined
  if (score >= 40) return 'yellow'; // Mixed
  return 'red'; // Emotional trading
};

/**
 * Calculate behavior heatmap for all time windows
 * @param {Array} trades - All trades to analyze
 * @param {Object} plan - Trading plan
 * @returns {Object} Heatmap data
 */
const calculateBehaviorHeatmap = (trades, plan) => {
  logger.info('[BehaviorHeatmap] Calculating for %d trades', trades.length);

  const windows = TIME_WINDOWS.map((window) => {
    // Filter trades for this window
    const windowTrades = trades.filter((trade) => {
      const tw = getTimeWindow(trade);
      return tw && tw.id === window.id;
    });

    if (windowTrades.length === 0) {
      return {
        ...window,
        score: null,
        color: 'grey',
        tradeCount: 0,
        metrics: null,
        message: 'No trades in this window',
      };
    }

    const { score, metrics } = calculateWindowScore(windowTrades, plan);
    const color = getColorStatus(score);

    logger.info('[BehaviorHeatmap] Window %s: score=%d trades=%d', window.id, score, windowTrades.length);

    return {
      ...window,
      score,
      color,
      tradeCount: windowTrades.length,
      metrics,
      message: getWindowMessage(color, metrics),
    };
  });

  return {
    windows,
    totalTrades: trades.length,
  };
};

const getWindowMessage = (color, metrics) => {
  if (color === 'green') return 'Disciplined trading in this window';

  const issues = [];
  if (metrics) {
    if (metrics.impulsiveness > 0) issues.push('Impulsiveness');
    if (metrics.hesitation > 0) issues.push('Hesitation');
    if (metrics.frequency > 0) issues.push('Overtrading');
    if (metrics.volatility > 0) issues.push('Volatility');
    if (metrics.riskDeviation > 10) issues.push('Risk Consistency');
    if (metrics.planCompliance < 85) issues.push('Plan Compliance');
  }

  // Fallback to ensure we always have a reason
  if (issues.length === 0) {
    issues.push('Plan Consistency');
  }

  const issueText = issues.slice(0, 2).join(' & ');

  if (color === 'yellow') {
    return `Mixed behavior - Watch: ${issueText}`;
  }

  return `Emotional trading detected - ${issueText}`;
};

/**
 * Derive a single insight from the heatmap analysis
 * @param {Array} windows - Processed window data
 * @returns {Object} Single insight
 */
const deriveHeatmapInsight = (windows) => {
  const insight = {
    type: 'neutral',
    message: null,
    recommendation: null,
  };

  // Filter windows with actual trades
  const activeWindows = windows.filter((w) => w.score !== null && w.tradeCount > 0);

  if (activeWindows.length === 0) {
    insight.message = 'Insufficient data to derive behavioral insights';
    return insight;
  }

  // Find best and worst performing windows
  const sortedByScore = [...activeWindows].sort((a, b) => b.score - a.score);
  const bestWindow = sortedByScore[0];
  const worstWindow = sortedByScore[sortedByScore.length - 1];

  // Find highest activity window
  const sortedByActivity = [...activeWindows].sort((a, b) => b.tradeCount - a.tradeCount);
  const highestActivityWindow = sortedByActivity[0];

  // Calculate correlations
  const highActivityBadBehavior = activeWindows.filter((w) => w.tradeCount >= 3 && w.score < 50).length;

  const lowActivityGoodBehavior = activeWindows.filter((w) => w.tradeCount <= 2 && w.score >= 70).length;

  const redWindows = activeWindows.filter((w) => w.color === 'red');
  const greenWindows = activeWindows.filter((w) => w.color === 'green');

  // Determine insight based on patterns
  if (highActivityBadBehavior > 0 && highestActivityWindow.score < 50) {
    insight.type = 'warning';
    insight.message = `Highest activity period (${highestActivityWindow.label}) correlates with lower discipline scores`;
    insight.recommendation = 'Consider reducing trade frequency during peak activity windows';
  } else if (lowActivityGoodBehavior > 0 && bestWindow.tradeCount <= 2) {
    insight.type = 'positive';
    insight.message = `Best discipline (${bestWindow.score}%) occurs during ${bestWindow.label} with fewer trades`;
    insight.recommendation = 'Lower trade frequency appears to improve decision quality';
  } else if (redWindows.length >= 2) {
    insight.type = 'warning';
    insight.message = `Emotional trading detected in ${redWindows.length} time windows - patterns need attention`;
    insight.recommendation = 'Review trades during red-flagged periods for common triggers';
  } else if (greenWindows.length >= activeWindows.length / 2) {
    insight.type = 'positive';
    insight.message = 'Disciplined trading across most active time windows';
    insight.recommendation = 'Maintain current approach - consistency is strong';
  } else if (worstWindow.score < 40 && bestWindow.score > 70) {
    insight.type = 'warning';
    insight.message = `Large behavior gap: ${bestWindow.label} (${bestWindow.score}%) vs ${worstWindow.label} (${worstWindow.score}%)`;
    insight.recommendation = `Consider avoiding ${worstWindow.label} or applying stricter rules during that time`;
  } else {
    insight.type = 'neutral';
    insight.message = 'Mixed behavioral patterns across time windows';
    insight.recommendation = 'Focus on improving consistency across all trading periods';
  }

  logger.info('[BehaviorHeatmap] Derived insight type: %s', insight.type);

  return insight;
};

/**
 * Enhanced behavior heatmap calculation with single insight
 */
const calculateBehaviorHeatmapWithInsight = (trades, plan) => {
  const baseResult = calculateBehaviorHeatmap(trades, plan);
  const insight = deriveHeatmapInsight(baseResult.windows);

  return {
    ...baseResult,
    insight,
  };
};

module.exports = {
  calculateBehaviorHeatmap,
  calculateBehaviorHeatmapWithInsight,
  calculateWindowScore,
  deriveHeatmapInsight,
  TIME_WINDOWS,
  getTimeWindow,
  calculateWinLossExpectancy,
  calculateImpulsivenessPenalty,
  calculateHesitationPenalty,
  calculateRiskDeviationPenalty,
  calculateVolatilityPenalty,
  calculateFrequencyPenalty,
};
