const logger = require('../../config/logger');

/**
 * Count impulsive trades in the last hour
 */
const countImpulsiveTradesLastHour = (trades) => {
  if (trades.length < 2) return 0;

  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const sortedTrades = [...trades]
    .filter((t) => new Date(t.entryTime) >= oneHourAgo)
    .sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  if (sortedTrades.length < 2) return 0;

  let impulsiveCount = 0;
  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffMinutes = (currEntry - prevExit) / (1000 * 60);
    if (diffMinutes < 30 && diffMinutes >= 0) {
      impulsiveCount++;
    }
  }

  return impulsiveCount;
};

/**
 * Calculate battery drop during session
 * Returns the maximum drop detected
 */
const calculateBatteryDrop = (startBattery, currentBattery) => {
  return Math.max(0, startBattery - currentBattery);
};

/**
 * Determine if breathwork should be suggested
 * Triggers if ANY:
 * - emotionalVolatility > 70
 * - mentalBattery < 40
 * - ≥3 impulsive trades in last hour
 * - battery drop > 30% during session
 *
 * @param {Object} params - Parameters for breathwork decision
 * @param {number} params.mentalBattery - Current mental battery level
 * @param {number} params.emotionalVolatility - Current emotional volatility score
 * @param {Array} params.todayTrades - Today's trades
 * @param {number} params.sessionStartBattery - Battery level at session start (default 100)
 * @returns {Object} Breathwork suggestion result
 */
const shouldSuggestBreathwork = ({ mentalBattery, emotionalVolatility, todayTrades, sessionStartBattery = 100 }) => {
  logger.info(
    '[Breathwork] Checking triggers - battery:%d volatility:%d trades:%d',
    mentalBattery,
    emotionalVolatility,
    todayTrades?.length || 0
  );

  const triggers = [];
  let shouldSuggest = false;

  // Trigger 1: emotionalVolatility > 70
  if (emotionalVolatility > 70) {
    triggers.push({
      type: 'high_volatility',
      value: emotionalVolatility,
      threshold: 70,
      message: 'High emotional volatility detected',
    });
    shouldSuggest = true;
    logger.info('[Breathwork] Trigger: High emotional volatility (%d > 70)', emotionalVolatility);
  }

  // Trigger 2: mentalBattery < 40
  if (mentalBattery < 40) {
    triggers.push({
      type: 'low_battery',
      value: mentalBattery,
      threshold: 40,
      message: 'Mental battery is critically low',
    });
    shouldSuggest = true;
    logger.info('[Breathwork] Trigger: Low mental battery (%d < 40)', mentalBattery);
  }

  // Trigger 3: ≥3 impulsive trades in last hour
  const impulsiveCount = countImpulsiveTradesLastHour(todayTrades || []);
  if (impulsiveCount >= 3) {
    triggers.push({
      type: 'impulsive_trades',
      value: impulsiveCount,
      threshold: 3,
      message: `${impulsiveCount} impulsive trades in the last hour`,
    });
    shouldSuggest = true;
    logger.info('[Breathwork] Trigger: Impulsive trades in last hour (%d >= 3)', impulsiveCount);
  }

  // Trigger 4: battery drop > 30% during session
  const batteryDrop = calculateBatteryDrop(sessionStartBattery, mentalBattery);
  if (batteryDrop > 30) {
    triggers.push({
      type: 'battery_drop',
      value: batteryDrop,
      threshold: 30,
      message: `Mental battery dropped ${batteryDrop}% during this session`,
    });
    shouldSuggest = true;
    logger.info('[Breathwork] Trigger: Battery drop (%d%% > 30%%)', batteryDrop);
  }

  // Calculate urgency level based on triggers
  const urgency = calculateUrgency(triggers, mentalBattery, emotionalVolatility);

  logger.info('[Breathwork] Should suggest: %s triggers: %d urgency: %s', shouldSuggest, triggers.length, urgency.level);

  return {
    shouldSuggest,
    urgency,
    triggers,
    message: shouldSuggest ? getUrgencyMessage(urgency.level) : 'Mental state is within acceptable range',
    breathworkType: shouldSuggest ? getRecommendedBreathwork(triggers) : null,
  };
};

/**
 * Calculate urgency level based on triggers and severity
 */
const calculateUrgency = (triggers, mentalBattery, emotionalVolatility) => {
  if (triggers.length === 0) {
    return { level: 'none', score: 0 };
  }

  let urgencyScore = 0;

  // Base score from number of triggers
  urgencyScore += triggers.length * 20;

  // Additional weight for severe conditions
  if (mentalBattery < 30) urgencyScore += 30;
  else if (mentalBattery < 40) urgencyScore += 15;

  if (emotionalVolatility > 80) urgencyScore += 25;
  else if (emotionalVolatility > 70) urgencyScore += 10;

  // Check for compounding triggers
  const hasMultipleSevere =
    triggers.filter((t) => ['low_battery', 'high_volatility', 'battery_drop'].includes(t.type)).length >= 2;

  if (hasMultipleSevere) urgencyScore += 20;

  // Determine level
  let level;
  if (urgencyScore >= 70) {
    level = 'high';
  } else if (urgencyScore >= 40) {
    level = 'medium';
  } else {
    level = 'low';
  }

  return {
    level,
    score: Math.min(100, urgencyScore),
    factors: triggers.map((t) => t.type),
  };
};

/**
 * Get message based on urgency level
 */
const getUrgencyMessage = (level) => {
  if (level === 'high') {
    return 'Immediate breathwork strongly recommended - multiple stress indicators detected';
  } else if (level === 'medium') {
    return 'Breathwork recommended now to help reset your mental state';
  } else {
    return 'A breathing exercise may help maintain focus';
  }
};

/**
 * Get recommended breathwork type based on triggers
 */
const getRecommendedBreathwork = (triggers) => {
  // Prioritize based on trigger type
  const hasVolatility = triggers.some((t) => t.type === 'high_volatility');
  const hasLowBattery = triggers.some((t) => t.type === 'low_battery');
  const hasImpulsive = triggers.some((t) => t.type === 'impulsive_trades');

  if (hasVolatility || hasImpulsive) {
    return {
      name: 'Box Breathing',
      duration: '4 minutes',
      pattern: '4-4-4-4',
      description: 'Inhale 4s, Hold 4s, Exhale 4s, Hold 4s',
    };
  }

  if (hasLowBattery) {
    return {
      name: 'Energizing Breath',
      duration: '3 minutes',
      pattern: '4-7-8',
      description: 'Inhale 4s, Hold 7s, Exhale 8s',
    };
  }

  return {
    name: 'Calming Breath',
    duration: '2 minutes',
    pattern: '4-4-6',
    description: 'Inhale 4s, Hold 4s, Exhale 6s',
  };
};

module.exports = {
  shouldSuggestBreathwork,
  countImpulsiveTradesLastHour,
  calculateBatteryDrop,
  calculateUrgency,
  getRecommendedBreathwork,
  getUrgencyMessage,
};
