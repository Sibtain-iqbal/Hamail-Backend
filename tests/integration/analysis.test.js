const mongoose = require('mongoose');
const request = require('supertest');
const httpStatus = require('http-status');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');
const { userOne, insertUsers } = require('../fixtures/user.fixture');
const { userOneAccessToken } = require('../fixtures/token.fixture');
const { tradeOne, tradeTwo, insertTrades } = require('../fixtures/trade.fixture');
const { tradingPlanOne, insertTradingPlans } = require('../fixtures/tradingPlan.fixture');

setupTestDB();

describe('Analysis routes', () => {
  describe('GET /v1/analysis/state', () => {
    test('should return 200 and current psychological state', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/state')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('state');
      expect(res.body).toHaveProperty('confidence');
      expect(res.body).toHaveProperty('planAdherence');
      expect(res.body).toHaveProperty('analyzedTradeCount');
      expect(res.body).toHaveProperty('indicators');
      expect(res.body).toHaveProperty('recommendations');
      expect(res.body).toHaveProperty('lastUpdated');
      expect(Array.isArray(res.body.indicators)).toBe(true);
      expect(Array.isArray(res.body.recommendations)).toBe(true);
      expect(typeof res.body.confidence).toBe('number');
      expect(res.body.confidence).toBeGreaterThanOrEqual(10);
      expect(res.body.confidence).toBeLessThanOrEqual(95);
    });

    test('should return 401 if access token is missing', async () => {
      await request(app).get('/v1/analysis/state').expect(httpStatus.UNAUTHORIZED);
    });

    test('should return STABLE state when no trades exist', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/state')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body.state).toBe('STABLE');
      expect(res.body.confidence).toBe(50);
      expect(res.body.planAdherence).toBe(50);
      expect(res.body.analyzedTradeCount).toBe(0);
      expect(res.body.recommendations).toContain('Record trades and set a trading plan to enable analysis');
    });

    test('should analyze state from recent trades', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      // Insert some trades for analysis
      const trades = [
        {
          ...tradeOne,
          userId: userOne._id,
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
          exitedEarly: false,
          stopLossHit: false,
        },
        {
          ...tradeTwo,
          userId: userOne._id,
          profitLoss: -75.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 0.0,
          exitedEarly: false,
          stopLossHit: true,
        },
      ];

      await insertTrades(trades);

      const res = await request(app)
        .get('/v1/analysis/state')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('state');
      expect(['STABLE', 'OVEREXTENDED', 'HESITANT', 'AGGRESSIVE']).toContain(res.body.state);
      expect(res.body).toHaveProperty('confidence');
      expect(res.body).toHaveProperty('planAdherence');
      expect(res.body).toHaveProperty('indicators');
      expect(res.body).toHaveProperty('recommendations');
      expect(Array.isArray(res.body.indicators)).toBe(true);
      expect(Array.isArray(res.body.recommendations)).toBe(true);
    });
  });

  describe('GET /v1/analysis/forecast', () => {
    test('should return 200 and session forecast', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/forecast')
        .query({ session: 'LONDON' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('session', 'LONDON');
      expect(res.body).toHaveProperty('predictedBias');
      expect(res.body).toHaveProperty('riskLevel');
      expect(res.body).toHaveProperty('forecast');
      expect(res.body).toHaveProperty('recommendations');
      expect(res.body).toHaveProperty('basedOnState');
      expect(Array.isArray(res.body.recommendations)).toBe(true);
      expect(['NEUTRAL', 'POSITIVE', 'NEGATIVE']).toContain(res.body.forecast);
      expect(['LOW', 'MEDIUM', 'HIGH']).toContain(res.body.riskLevel);
    });

    test('should return 401 if access token is missing', async () => {
      await request(app).get('/v1/analysis/forecast').query({ session: 'LONDON' }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return neutral forecast when no trades exist for session', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/forecast')
        .query({ session: 'LONDON' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body.session).toBe('LONDON');
      expect(res.body.forecast).toBe('NEUTRAL');
      expect(res.body.predictedBias).toBe('NEUTRAL');
      expect(res.body.riskLevel).toBe('MEDIUM');
      expect(res.body.recommendations).toContain('Log more trades in this session to improve forecast');
    });

    test('should analyze forecast from session-specific trades', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      // Insert trades for LONDON session
      const londonTrades = [
        {
          ...tradeOne,
          userId: userOne._id,
          session: 'LONDON',
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
        },
        {
          ...tradeTwo,
          userId: userOne._id,
          session: 'LONDON',
          profitLoss: 100.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 80.0,
        },
      ];

      await insertTrades(londonTrades);

      const res = await request(app)
        .get('/v1/analysis/forecast')
        .query({ session: 'LONDON' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body.session).toBe('LONDON');
      expect(res.body).toHaveProperty('forecast');
      expect(res.body).toHaveProperty('predictedBias');
      expect(res.body).toHaveProperty('riskLevel');
      expect(res.body).toHaveProperty('recommendations');
      expect(res.body).toHaveProperty('basedOnState');
    });
  });

  describe('GET /v1/analysis/insights', () => {
    test('should return 200 and performance insights', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/insights')
        .query({ period: 'MONTH' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('period', 'MONTH');
      expect(res.body).toHaveProperty('insights');
      expect(res.body).toHaveProperty('stats');
      expect(res.body).toHaveProperty('recommendations');
      expect(Array.isArray(res.body.insights)).toBe(true);
      expect(res.body.stats).toHaveProperty('winRate');
      expect(res.body.stats).toHaveProperty('avgRiskReward');
      expect(res.body.stats).toHaveProperty('planAdherence');
      expect(res.body.stats).toHaveProperty('tradesThisWeek');
    });

    test('should return 401 if access token is missing', async () => {
      await request(app).get('/v1/analysis/insights').query({ period: 'MONTH' }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return default insights when no trades exist', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/insights')
        .query({ period: 'MONTH' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body.period).toBe('MONTH');
      expect(Array.isArray(res.body.insights)).toBe(true);
      expect(res.body.insights.length).toBeGreaterThan(0);
      expect(res.body.insights[0]).toHaveProperty('type');
      expect(res.body.insights[0]).toHaveProperty('title');
      expect(res.body.insights[0]).toHaveProperty('description');
    });

    test('should analyze insights from trades in specified period', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      // Insert trades for analysis
      const trades = [
        {
          ...tradeOne,
          userId: userOne._id,
          entryTime: new Date('2023-01-01T09:00:00Z'),
          profitLoss: 150.0,
          riskPercentUsed: 2.0,
          targetPercentAchieved: 100.0,
        },
        {
          ...tradeTwo,
          userId: userOne._id,
          entryTime: new Date('2023-01-02T14:00:00Z'),
          profitLoss: -75.0,
          riskPercentUsed: 1.5,
          targetPercentAchieved: 0.0,
        },
      ];

      await insertTrades(trades);

      const res = await request(app)
        .get('/v1/analysis/insights')
        .query({ period: 'MONTH' })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body.period).toBe('MONTH');
      expect(res.body).toHaveProperty('insights');
      expect(res.body).toHaveProperty('stats');
      expect(res.body).toHaveProperty('recommendations');
      expect(Array.isArray(res.body.insights)).toBe(true);
    });
  });

  describe('GET /v1/analysis/history', () => {
    test('should return 200 and state history', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/history')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('history');
      expect(res.body).toHaveProperty('summary');
      expect(Array.isArray(res.body.history)).toBe(true);
      expect(res.body.summary).toHaveProperty('totalChanges');
      expect(res.body.summary).toHaveProperty('mostCommonState');
      expect(res.body.summary).toHaveProperty('averageConfidence');
      expect(res.body.summary).toHaveProperty('volatility');
    });

    test('should return 401 if access token is missing', async () => {
      await request(app).get('/v1/analysis/history').expect(httpStatus.UNAUTHORIZED);
    });

    test('should apply date filters correctly', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const startDate = new Date('2023-01-01').toISOString();
      const endDate = new Date('2023-01-31').toISOString();

      const res = await request(app)
        .get('/v1/analysis/history')
        .query({ startDate, endDate })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('history');
      expect(Array.isArray(res.body.history)).toBe(true);
    });

    test('should apply limit filter correctly', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const trades = Array.from({ length: 20 }, (_, i) => ({
        ...tradeOne,
        userId: userOne._id,
        _id: mongoose.Types.ObjectId(),
        entryTime: new Date(`2023-01-${String(i + 1).padStart(2, '0')}T09:00:00Z`),
        profitLoss: i % 2 === 0 ? 100 : -50,
        riskPercentUsed: 2.0,
      }));

      await insertTrades(trades);

      const res = await request(app)
        .get('/v1/analysis/history')
        .query({ limit: 5 })
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('history');
      expect(Array.isArray(res.body.history)).toBe(true);
      expect(res.body.history.length).toBeLessThanOrEqual(5);
    });

    test('should return empty history when no trades exist', async () => {
      await insertUsers([userOne]);
      const plan = { ...tradingPlanOne, userId: userOne._id };
      await insertTradingPlans([plan]);

      const res = await request(app)
        .get('/v1/analysis/history')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.OK);

      expect(res.body).toHaveProperty('history');
      expect(res.body).toHaveProperty('summary');
      expect(Array.isArray(res.body.history)).toBe(true);
      expect(res.body.summary.totalChanges).toBe(0);
    });
  });
});
