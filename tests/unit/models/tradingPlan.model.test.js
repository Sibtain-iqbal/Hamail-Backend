const mongoose = require('mongoose');
const { TradingPlan } = require('../../../src/models');
const { TradingSessions, StopLossDisciplines } = require('../../../src/models/enums');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('TradingPlan model', () => {
  let tradingPlanData;

  beforeEach(() => {
    tradingPlanData = {
      userId: mongoose.Types.ObjectId(),
      maxTradesPerDay: 5,
      riskPercentPerTrade: 2.0,
      targetRiskRewardRatio: 2.0,
      preferredSessions: [TradingSessions.LONDON, TradingSessions.NY],
      stopLossDiscipline: StopLossDisciplines.STRICT,
    };
  });

  test('should create trading plan successfully', async () => {
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan._id).toBeDefined();
    expect(savedTradingPlan.userId.toString()).toBe(tradingPlanData.userId.toString());
    expect(savedTradingPlan.maxTradesPerDay).toBe(tradingPlanData.maxTradesPerDay);
    expect(savedTradingPlan.riskPercentPerTrade).toBe(tradingPlanData.riskPercentPerTrade);
    expect(savedTradingPlan.targetRiskRewardRatio).toBe(tradingPlanData.targetRiskRewardRatio);
    expect(savedTradingPlan.preferredSessions).toEqual(tradingPlanData.preferredSessions);
    expect(savedTradingPlan.stopLossDiscipline).toBe(tradingPlanData.stopLossDiscipline);
    expect(savedTradingPlan.createdAt).toBeDefined();
    expect(savedTradingPlan.updatedAt).toBeDefined();
  });

  test('should require userId', async () => {
    delete tradingPlanData.userId;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should require maxTradesPerDay', async () => {
    delete tradingPlanData.maxTradesPerDay;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should require riskPercentPerTrade', async () => {
    delete tradingPlanData.riskPercentPerTrade;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should require targetRiskRewardRatio', async () => {
    delete tradingPlanData.targetRiskRewardRatio;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should require stopLossDiscipline', async () => {
    delete tradingPlanData.stopLossDiscipline;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should validate maxTradesPerDay minimum value', async () => {
    tradingPlanData.maxTradesPerDay = -1;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should validate riskPercentPerTrade minimum value', async () => {
    tradingPlanData.riskPercentPerTrade = -1;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should validate targetRiskRewardRatio minimum value', async () => {
    tradingPlanData.targetRiskRewardRatio = -1;
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should validate preferredSessions enum values', async () => {
    tradingPlanData.preferredSessions = ['INVALID_SESSION'];
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should validate stopLossDiscipline enum value', async () => {
    tradingPlanData.stopLossDiscipline = 'INVALID_DISCIPLINE';
    const tradingPlan = new TradingPlan(tradingPlanData);

    await expect(tradingPlan.save()).rejects.toThrow();
  });

  test('should allow empty preferredSessions array', async () => {
    tradingPlanData.preferredSessions = [];
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan.preferredSessions).toEqual([]);
  });

  test('should allow single preferred session', async () => {
    tradingPlanData.preferredSessions = [TradingSessions.LONDON];
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan.preferredSessions).toEqual([TradingSessions.LONDON]);
  });

  test('should allow all trading sessions', async () => {
    tradingPlanData.preferredSessions = Object.values(TradingSessions);
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan.preferredSessions).toEqual(Object.values(TradingSessions));
  });

  test('should allow all stop loss disciplines', async () => {
    Object.values(StopLossDisciplines).forEach(async (discipline) => {
      tradingPlanData.stopLossDiscipline = discipline;
      const tradingPlan = new TradingPlan(tradingPlanData);
      const savedTradingPlan = await tradingPlan.save();

      expect(savedTradingPlan.stopLossDiscipline).toBe(discipline);
    });
  });

  test('should have toJSON plugin applied', async () => {
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();
    const json = savedTradingPlan.toJSON();

    expect(json).not.toHaveProperty('_id');
    expect(json).not.toHaveProperty('__v');
    expect(json).toHaveProperty('id');
    expect(json.id).toBe(savedTradingPlan._id.toString());
  });

  test('should have proper indexes', async () => {
    const indexes = TradingPlan.collection.getIndexes();
    expect(indexes).toHaveProperty('userId_1');
  });

  test('should handle decimal values correctly', async () => {
    tradingPlanData.riskPercentPerTrade = 1.5;
    tradingPlanData.targetRiskRewardRatio = 2.5;
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan.riskPercentPerTrade).toBe(1.5);
    expect(savedTradingPlan.targetRiskRewardRatio).toBe(2.5);
  });

  test('should handle zero values correctly', async () => {
    tradingPlanData.maxTradesPerDay = 0;
    tradingPlanData.riskPercentPerTrade = 0;
    tradingPlanData.targetRiskRewardRatio = 0;
    const tradingPlan = new TradingPlan(tradingPlanData);
    const savedTradingPlan = await tradingPlan.save();

    expect(savedTradingPlan.maxTradesPerDay).toBe(0);
    expect(savedTradingPlan.riskPercentPerTrade).toBe(0);
    expect(savedTradingPlan.targetRiskRewardRatio).toBe(0);
  });
});
