const logger = require('../../config/logger');
const { calculatePlanControl } = require('./planControl');

/**
 * Calculate Discipline score (0-100)
 * Base = PlanControl%
 * +10 if no risk breaches
 * +5 if no session violations
 */
const calculateDiscipline = (trades, plan, planControlPercent) => {
  let score = planControlPercent;
  const planRisk = plan?.riskPercentPerTrade || 1;
  const preferredSessions = plan?.preferredSessions || [];

  // +10 if no risk breaches (all trades within ±30% of planRisk)
  const hasRiskBreach = trades.some((t) => t.riskPercentUsed && t.riskPercentUsed > planRisk * 1.3);
  if (!hasRiskBreach) {
    score += 10;
  }

  // +5 if no session violations
  const hasSessionViolation = preferredSessions.length > 0 && trades.some((t) => !preferredSessions.includes(t.session));
  if (!hasSessionViolation) {
    score += 5;
  }

  return Math.min(100, Math.round(score));
};

/**
 * Calculate Impulse Control score (0-100)
 * impulsiveCount = entries < 30 mins from previous exit
 * raw = (impulsiveCount / 5) * 100
 * impulseControl = 100 - raw
 */
const calculateImpulseControl = (trades) => {
  if (trades.length < 2) return 100; // Perfect impulse control with 0-1 trades

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

  const raw = (impulsiveCount / 5) * 100;
  return Math.max(0, Math.round(100 - raw));
};

/**
 * Calculate Aggression score (0-100)
 * Base = avg(riskUsed / planRisk) * 50
 * +20 if any trade > 1.5x planRisk
 * +15 if revenge trade occurs
 */
const calculateAggression = (trades, plan) => {
  if (trades.length === 0) return 0;

  const planRisk = plan?.riskPercentPerTrade || 1;

  // Calculate base from average risk usage
  const risksUsed = trades.filter((t) => t.riskPercentUsed).map((t) => t.riskPercentUsed);
  let base = 0;
  if (risksUsed.length > 0) {
    const avgRisk = risksUsed.reduce((a, b) => a + b, 0) / risksUsed.length;
    base = (avgRisk / planRisk) * 50;
  }

  // +20 if any trade > 1.5x planRisk
  const hasHighRisk = trades.some((t) => t.riskPercentUsed && t.riskPercentUsed > planRisk * 1.5);
  if (hasHighRisk) {
    base += 20;
  }

  // +15 if revenge trade occurs (loss followed by oversized trade)
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let hasRevengeTrade = false;
  for (let i = 1; i < sortedTrades.length; i++) {
    const prevTrade = sortedTrades[i - 1];
    const currTrade = sortedTrades[i];
    if (prevTrade.profitLoss < 0 && currTrade.riskPercentUsed && currTrade.riskPercentUsed > planRisk * 1.3) {
      hasRevengeTrade = true;
      break;
    }
  }
  if (hasRevengeTrade) {
    base += 15;
  }

  return Math.min(100, Math.round(base));
};

/**
 * Calculate Hesitation score (0-100)
 * hesitationCount = early exits OR low target wins
 * hesitation = (count / 5) * 100
 * +20 if targetPercentAchieved < 60 on winning trades
 * +15 if skipped setups detected (gaps > 4 hours with no trades)
 */
const calculateHesitation = (trades) => {
  if (trades.length === 0) return 0;

  let hesitationCount = 0;

  // Count early exits
  trades.forEach((trade) => {
    if (trade.exitedEarly) {
      hesitationCount++;
    }
  });

  let base = (hesitationCount / 5) * 100;

  // +20 if targetPercentAchieved < 60 on winning trades
  const hasLowTargetWins = trades.some((t) => t.profitLoss > 0 && t.targetPercentAchieved && t.targetPercentAchieved < 60);
  if (hasLowTargetWins) {
    base += 20;
  }

  // +15 if skipped setups detected (gaps > 4 hours)
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let hasLongGap = false;
  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffHours = (currEntry - prevExit) / (1000 * 60 * 60);
    if (diffHours > 4) {
      hasLongGap = true;
      break;
    }
  }
  if (hasLongGap) {
    base += 15;
  }

  return Math.min(100, Math.round(base));
};

/**
 * Calculate Consistency score (0-100)
 * variability = (stdDevRisk / avgRisk) * 100
 * consistency = 100 - variability
 * +10 if all trades in preferred sessions
 * +5 if stable timing patterns
 */
const calculateConsistency = (trades, plan) => {
  if (trades.length === 0) return 100;

  const preferredSessions = plan?.preferredSessions || [];

  // Calculate variability from risk usage
  const risksUsed = trades.filter((t) => t.riskPercentUsed).map((t) => t.riskPercentUsed);
  let variability = 0;

  if (risksUsed.length > 1) {
    const avgRisk = risksUsed.reduce((a, b) => a + b, 0) / risksUsed.length;
    const variance = risksUsed.reduce((sum, val) => sum + Math.pow(val - avgRisk, 2), 0) / risksUsed.length;
    const stdDev = Math.sqrt(variance);
    variability = avgRisk > 0 ? (stdDev / avgRisk) * 100 : 0;
  }

  let score = 100 - variability;

  // +10 if all trades in preferred sessions
  const allInPreferred = preferredSessions.length === 0 || trades.every((t) => preferredSessions.includes(t.session));
  if (allInPreferred) {
    score += 10;
  }

  // +5 if stable timing patterns (trades spaced 1-4 hours apart)
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let stableTiming = true;
  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffHours = (currEntry - prevExit) / (1000 * 60 * 60);
    if (diffHours < 0.5 || diffHours > 6) {
      stableTiming = false;
      break;
    }
  }
  if (stableTiming && trades.length > 1) {
    score += 5;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
};

/**
 * Calculate Emotional Volatility score (0-100)
 * volatility = |aggression - hesitation| / 2
 * If both aggression and hesitation > 60 → +20
 */
const calculateEmotionalVolatility = (aggressionScore, hesitationScore) => {
  let volatility = Math.abs(aggressionScore - hesitationScore) / 2;

  // If both are high, add penalty
  if (aggressionScore > 60 && hesitationScore > 60) {
    volatility += 20;
  }

  return Math.min(100, Math.round(volatility));
};

/**
 * Calculate all psychological radar traits
 * @param {Array} trades - Last 5 trades
 * @param {Object} plan - Trading plan
 * @returns {Object} Radar chart data
 */
const calculatePsychologicalRadar = (trades, plan) => {
  logger.info('[PsychologicalRadar] Calculating for %d trades', trades.length);

  if (!trades || trades.length === 0) {
    return {
      traits: {
        discipline: 0,
        impulseControl: 100,
        aggression: 0,
        hesitation: 0,
        consistency: 100,
        emotionalVolatility: 0,
      },
      tradesAnalyzed: 0,
      message: 'No trades to analyze',
    };
  }

  // Take last 5 trades
  const recentTrades = trades.slice(0, 5);

  // Calculate plan control for discipline base
  const { percentage: planControlPercent } = calculatePlanControl(recentTrades, plan);

  // Calculate all traits
  const discipline = calculateDiscipline(recentTrades, plan, planControlPercent);
  const impulseControl = calculateImpulseControl(recentTrades);
  const aggression = calculateAggression(recentTrades, plan);
  const hesitation = calculateHesitation(recentTrades);
  const consistency = calculateConsistency(recentTrades, plan);
  const emotionalVolatility = calculateEmotionalVolatility(aggression, hesitation);

  logger.info(
    '[PsychologicalRadar] Traits - discipline:%d impulseControl:%d aggression:%d hesitation:%d consistency:%d volatility:%d',
    discipline,
    impulseControl,
    aggression,
    hesitation,
    consistency,
    emotionalVolatility
  );

  return {
    traits: {
      discipline,
      impulseControl,
      aggression,
      hesitation,
      consistency,
      emotionalVolatility,
    },
    tradesAnalyzed: recentTrades.length,
    message: getRadarMessage(discipline, impulseControl, aggression, emotionalVolatility),
  };
};

const getRadarMessage = (discipline, impulseControl, aggression, volatility) => {
  if (discipline >= 70 && impulseControl >= 70 && volatility < 30) {
    return 'Psychological profile shows strong discipline and control';
  }
  if (aggression > 70) {
    return 'High aggression detected - consider reviewing risk management';
  }
  if (impulseControl < 50) {
    return 'Low impulse control - practice patience between trades';
  }
  if (volatility > 60) {
    return 'Emotional volatility detected - consider taking a break';
  }
  return 'Balanced psychological state with areas for improvement';
};

module.exports = {
  calculatePsychologicalRadar,
  calculateDiscipline,
  calculateImpulseControl,
  calculateAggression,
  calculateHesitation,
  calculateConsistency,
  calculateEmotionalVolatility,
};
