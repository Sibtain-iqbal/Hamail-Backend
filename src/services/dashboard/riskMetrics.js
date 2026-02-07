/**
 * Calculate risk metrics from trades
 * @param {Array} trades
 * @returns {Object}
 */
const calculateRiskMetrics = (trades) => {
  if (trades.length === 0) {
    return {
      averageRiskPerTrade: 0,
      maxDrawdown: 0,
      sharpeRatio: 0,
    };
  }

  // Calculate averageRiskPerTrade only from trades with non-null riskPercentUsed
  const tradesWithRisk = trades.filter((t) => t.riskPercentUsed != null);
  const averageRiskPerTrade =
    tradesWithRisk.length > 0 ? tradesWithRisk.reduce((sum, t) => sum + t.riskPercentUsed, 0) / tradesWithRisk.length : 0;

  // Calculate max drawdown
  let peak = 0;
  let maxDrawdown = 0;
  let runningPnL = 0;

  trades.forEach((trade) => {
    runningPnL += trade.profitLoss;
    if (runningPnL > peak) {
      peak = runningPnL;
    }
    const drawdown = peak - runningPnL;
    if (drawdown > maxDrawdown) {
      maxDrawdown = drawdown;
    }
  });

  // Calculate Sharpe ratio (simplified)
  const returns = trades.map((t) => t.profitLoss);
  const avgReturn = returns.reduce((sum, r) => sum + r, 0) / returns.length;
  const variance = returns.reduce((sum, r) => sum + (r - avgReturn) ** 2, 0) / returns.length;
  const stdDev = Math.sqrt(variance);
  const sharpeRatio = stdDev > 0 ? avgReturn / stdDev : 0;

  return {
    averageRiskPerTrade: Math.round(averageRiskPerTrade * 100) / 100,
    maxDrawdown: Math.round(maxDrawdown * 100) / 100,
    sharpeRatio: Math.round(sharpeRatio * 100) / 100,
  };
};

module.exports = calculateRiskMetrics;
