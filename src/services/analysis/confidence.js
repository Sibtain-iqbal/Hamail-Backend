/**
 * Calculate confidence score (10-95) with small-N cap
 * @param {Object} metrics
 * @param {number} planAdherence
 * @param {number} planRisk
 * @param {number} totalTrades
 * @returns {number}
 */
const calculateConfidence = (metrics, planAdherence, planRisk, totalTrades) => {
  const { winRate, avgRiskUsed, medianTargetPct } = metrics;

  const sampleFactor = Math.min(totalTrades, 10) / 10;
  const discipline = planAdherence / 100;
  const signalStrength = Math.max(
    Math.abs((planRisk ? avgRiskUsed / planRisk : 1) - 1),
    Math.abs(winRate - 0.5) * 2,
    Math.abs((medianTargetPct || 0) / 100 - 0.6)
  );

  let confidence = Math.round(100 * (0.5 * discipline + 0.3 * sampleFactor + 0.2 * signalStrength));
  confidence = Math.max(10, Math.min(95, confidence));

  // Cap confidence for small sample sizes
  if (totalTrades < 5) {
    confidence = Math.min(confidence, 40);
  }

  return confidence;
};

module.exports = calculateConfidence;
