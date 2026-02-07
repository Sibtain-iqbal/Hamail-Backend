const computeMedian = (sortedNumbers) => {
  if (!Array.isArray(sortedNumbers) || sortedNumbers.length === 0) return 0;
  const midIdx = Math.floor(sortedNumbers.length / 2);
  if (sortedNumbers.length % 2 === 1) {
    return sortedNumbers[midIdx];
  }
  return (sortedNumbers[midIdx - 1] + sortedNumbers[midIdx]) / 2;
};

module.exports = computeMedian;
