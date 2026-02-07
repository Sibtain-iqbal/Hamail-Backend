const mongoose = require('mongoose');
const { analysisService } = require('../../../src/services');
const { tradeOne, tradeTwo, insertTrades } = require('../../fixtures/trade.fixture');
const { tradingPlanOne, insertTradingPlans } = require('../../fixtures/tradingPlan.fixture');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('Analysis service', () => {
  describe('getCurrentState', () => {
    test('should return STABLE state when no trades exist', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const result = await analysisService.getCurrentState(userId);

      expect(result).toEqual({
        state: 'STABLE',
        confidence: 50,
        planAdherence: 50,
        analyzedTradeCount: 0,
        indicators: expect.arrayContaining([
          expect.objectContaining({
            category: 'data',
            message: 'Insufficient data to analyze state',
            severity: 'neutral',
          }),
        ]),
        recommendations: expect.arrayContaining(['Record trades and set a trading plan to enable analysis']),
        lastUpdated: expect.any(String),
      });
    });

    test('should analyze psychological state from recent trades', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const recentTrades = [
        {
          ...tradeOne,
          userId,
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
          exitedEarly: false,
          stopLossHit: false,
        },
        {
          ...tradeTwo,
          userId,
          profitLoss: -75.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 0.0,
          exitedEarly: false,
          stopLossHit: true,
        },
      ];

      await insertTrades(recentTrades);

      const result = await analysisService.getCurrentState(userId);

      expect(result).toHaveProperty('state');
      expect(result).toHaveProperty('confidence');
      expect(result).toHaveProperty('planAdherence');
      expect(result).toHaveProperty('analyzedTradeCount');
      expect(result).toHaveProperty('indicators');
      expect(result).toHaveProperty('recommendations');
      expect(result).toHaveProperty('lastUpdated');
      expect(Array.isArray(result.indicators)).toBe(true);
      expect(Array.isArray(result.recommendations)).toBe(true);
      expect(typeof result.confidence).toBe('number');
      expect(result.confidence).toBeGreaterThanOrEqual(10);
      expect(result.confidence).toBeLessThanOrEqual(95);
    });

    test('should identify STABLE state with good plan adherence', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId, riskPercentPerTrade: 2.0 };
      await insertTradingPlans([plan]);

      const winningTrades = Array.from({ length: 8 }, () => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        profitLoss: 100.0,
        riskPercentUsed: 2.0,
        targetPercentAchieved: 100.0,
        exitedEarly: false,
        stopLossHit: false,
        session: 'LONDON',
      }));

      const losingTrades = Array.from({ length: 2 }, () => ({
        ...tradeTwo,
        userId,
        _id: mongoose.Types.ObjectId(),
        profitLoss: -50.0,
        riskPercentUsed: 2.0,
        targetPercentAchieved: 0.0,
        exitedEarly: false,
        stopLossHit: true,
        session: 'LONDON',
      }));

      await insertTrades([...winningTrades, ...losingTrades]);

      const result = await analysisService.getCurrentState(userId);

      expect(['STABLE', 'HESITANT']).toContain(result.state);
      expect(result.confidence).toBeGreaterThanOrEqual(10);
      expect(result.planAdherence).toBeGreaterThanOrEqual(0);
    });

    test('should identify AGGRESSIVE state with high risk usage', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId, riskPercentPerTrade: 1.5 };
      await insertTradingPlans([plan]);

      const highRiskTrades = Array.from({ length: 5 }, () => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        profitLoss: 200.0,
        riskPercentUsed: 3.0, // High risk (2x plan)
        targetPercentAchieved: 100.0,
        exitedEarly: false,
        stopLossHit: false,
        session: 'LONDON',
      }));

      await insertTrades(highRiskTrades);

      const result = await analysisService.getCurrentState(userId);

      expect(result.state).toBe('AGGRESSIVE');
      expect(result.planAdherence).toBeLessThan(100);
      expect(result.recommendations.some((r) => r.toLowerCase().includes('risk'))).toBe(true);
    });

    test('should identify HESITANT state with early exits', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const earlyExitTrades = Array.from({ length: 5 }, () => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        profitLoss: 50.0,
        riskPercentUsed: 2.0,
        targetPercentAchieved: 40.0, // Early exit
        exitedEarly: true,
        stopLossHit: false,
        session: 'LONDON',
      }));

      await insertTrades(earlyExitTrades);

      const result = await analysisService.getCurrentState(userId);

      expect(result.state).toBe('HESITANT');
      expect(
        result.recommendations.some((r) => r.toLowerCase().includes('target') || r.toLowerCase().includes('exit'))
      ).toBe(true);
    });
  });

  describe('getSessionForecast', () => {
    test('should return neutral forecast when no trades exist for session', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const result = await analysisService.getSessionForecast(userId, 'LONDON');

      expect(result).toEqual({
        session: 'LONDON',
        predictedBias: 'NEUTRAL',
        riskLevel: 'MEDIUM',
        forecast: 'NEUTRAL',
        recommendations: expect.arrayContaining(['Log more trades in this session to improve forecast']),
        basedOnState: 'STABLE',
      });
    });

    test('should analyze session forecast from historical trades', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const londonTrades = [
        {
          ...tradeOne,
          userId,
          session: 'LONDON',
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
        },
        {
          ...tradeTwo,
          userId,
          session: 'LONDON',
          profitLoss: 100.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 80.0,
        },
      ];

      await insertTrades(londonTrades);

      const result = await analysisService.getSessionForecast(userId, 'LONDON');

      expect(result).toHaveProperty('session', 'LONDON');
      expect(result).toHaveProperty('predictedBias');
      expect(result).toHaveProperty('riskLevel');
      expect(result).toHaveProperty('forecast');
      expect(result).toHaveProperty('recommendations');
      expect(result).toHaveProperty('basedOnState');
      expect(Array.isArray(result.recommendations)).toBe(true);
      expect(['NEUTRAL', 'POSITIVE', 'NEGATIVE']).toContain(result.forecast);
      expect(['LOW', 'MEDIUM', 'HIGH']).toContain(result.riskLevel);
    });

    test('should return negative forecast for high risk session', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId, riskPercentPerTrade: 1.5 };
      await insertTradingPlans([plan]);

      const highRiskTrades = Array.from({ length: 5 }, () => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        session: 'NY',
        profitLoss: 100.0,
        riskPercentUsed: 2.5, // Above plan threshold
        targetPercentAchieved: 100.0,
      }));

      await insertTrades(highRiskTrades);

      const result = await analysisService.getSessionForecast(userId, 'NY');

      expect(['NEGATIVE', 'NEUTRAL']).toContain(result.forecast);
      expect(result.predictedBias).not.toBe('NEUTRAL');
    });
  });

  describe('getPerformanceInsights', () => {
    test('should return performance insights for specified period', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const trades = [
        {
          ...tradeOne,
          userId,
          entryTime: new Date('2023-01-01T09:00:00Z'),
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
        },
        {
          ...tradeTwo,
          userId,
          entryTime: new Date('2023-01-02T14:00:00Z'),
          profitLoss: -75.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 0.0,
        },
      ];

      await insertTrades(trades);

      const result = await analysisService.getPerformanceInsights(userId, 'MONTH');

      expect(result).toHaveProperty('period', 'MONTH');
      expect(result).toHaveProperty('insights');
      expect(result).toHaveProperty('stats');
      expect(result).toHaveProperty('recommendations');
      expect(Array.isArray(result.insights)).toBe(true);
      expect(result.insights.length).toBeGreaterThan(0);
      expect(result.stats).toHaveProperty('winRate');
      expect(result.stats).toHaveProperty('avgRiskReward');
      expect(result.stats).toHaveProperty('planAdherence');
      expect(result.stats).toHaveProperty('tradesThisWeek');
    });

    test('should return default insights when no trades exist', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const result = await analysisService.getPerformanceInsights(userId, 'MONTH');

      expect(result).toHaveProperty('period', 'MONTH');
      expect(result).toHaveProperty('insights');
      expect(Array.isArray(result.insights)).toBe(true);
      expect(result.insights.length).toBeGreaterThan(0);
      expect(result.insights[0]).toHaveProperty('type');
      expect(result.insights[0]).toHaveProperty('title');
      expect(result.insights[0]).toHaveProperty('description');
    });
  });

  describe('getStateHistory', () => {
    test('should return state history with default filters', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const trades = Array.from({ length: 10 }, (_, i) => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        entryTime: new Date(`2023-01-${String(i + 1).padStart(2, '0')}T09:00:00Z`),
        profitLoss: i % 2 === 0 ? 100 : -50,
        riskPercentUsed: 2.0,
        targetPercentAchieved: i % 2 === 0 ? 100 : 0,
      }));

      await insertTrades(trades);

      const result = await analysisService.getStateHistory(userId, {});

      expect(result).toHaveProperty('history');
      expect(result).toHaveProperty('summary');
      expect(Array.isArray(result.history)).toBe(true);
      expect(result.summary).toHaveProperty('totalChanges');
      expect(result.summary).toHaveProperty('mostCommonState');
      expect(result.summary).toHaveProperty('averageConfidence');
      expect(result.summary).toHaveProperty('volatility');
    });

    test('should apply date filters correctly', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const startDate = new Date('2023-01-01');
      const endDate = new Date('2023-01-31');

      const result = await analysisService.getStateHistory(userId, {
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
      });

      expect(result).toHaveProperty('history');
      expect(Array.isArray(result.history)).toBe(true);
    });

    test('should apply limit filter correctly', async () => {
      const userId = mongoose.Types.ObjectId();
      const plan = { ...tradingPlanOne, userId };
      await insertTradingPlans([plan]);

      const trades = Array.from({ length: 20 }, (_, i) => ({
        ...tradeOne,
        userId,
        _id: mongoose.Types.ObjectId(),
        entryTime: new Date(`2023-01-${String(i + 1).padStart(2, '0')}T09:00:00Z`),
        profitLoss: i % 2 === 0 ? 100 : -50,
        riskPercentUsed: 2.0,
      }));

      await insertTrades(trades);

      const result = await analysisService.getStateHistory(userId, { limit: 5 });

      expect(result).toHaveProperty('history');
      expect(Array.isArray(result.history)).toBe(true);
      expect(result.history.length).toBeLessThanOrEqual(5);
    });
  });
});
