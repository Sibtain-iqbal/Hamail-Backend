/**
 * Get state trigger description from trade
 * @param {Object} trade
 * @returns {string}
 */
const getStateTrigger = (trade) => {
  if (trade.profitLoss > 0) return 'Profitable trade';
  if (trade.profitLoss < 0) return 'Losing trade';
  if (trade.exitedEarly) return 'Early exit';
  if (trade.stopLossHit) return 'Stop loss hit';
  return 'Trade execution';
};

module.exports = getStateTrigger;
