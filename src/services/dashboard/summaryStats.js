/**
 * Calculate summary statistics from trades
 * @param {Array} trades
 * @returns {Object}
 */
const calculateSummaryStats = (trades) => {
  if (trades.length === 0) {
    return {
      totalTrades: 0,
      winningTrades: 0,
      losingTrades: 0,
      winRate: 0,
      totalProfitLoss: 0,
      averageRiskReward: 0,
      bestTrade: 0,
      worstTrade: 0,
    };
  }

  const totalTrades = trades.length;
  const winningTrades = trades.filter((t) => t.profitLoss > 0).length;
  const losingTrades = trades.filter((t) => t.profitLoss < 0).length;
  const winRate = totalTrades > 0 ? (winningTrades / totalTrades) * 100 : 0;
  const totalProfitLoss = trades.reduce((sum, t) => sum + t.profitLoss, 0);

  // Calculate averageRiskReward only from trades with non-null riskRewardAchieved
  const tradesWithRR = trades.filter((t) => t.riskRewardAchieved != null);
  const averageRiskReward =
    tradesWithRR.length > 0 ? tradesWithRR.reduce((sum, t) => sum + t.riskRewardAchieved, 0) / tradesWithRR.length : 0;
  const profits = trades.map((t) => t.profitLoss);
  const bestTrade = Math.max(...profits);
  const worstTrade = Math.min(...profits);

  return {
    totalTrades,
    winningTrades,
    losingTrades,
    winRate: Math.round(winRate * 100) / 100,
    totalProfitLoss: Math.round(totalProfitLoss * 100) / 100,
    averageRiskReward: Math.round(averageRiskReward * 100) / 100,
    bestTrade: Math.round(bestTrade * 100) / 100,
    worstTrade: Math.round(worstTrade * 100) / 100,
  };
};

module.exports = calculateSummaryStats;
