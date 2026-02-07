const request = require('supertest');
const httpStatus = require('http-status');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');
const { TradingPlan } = require('../../src/models');
const { userOne, insertUsers } = require('../fixtures/user.fixture');
const { userOneAccessToken } = require('../fixtures/token.fixture');
const { tradingPlanOne, insertTradingPlans } = require('../fixtures/tradingPlan.fixture');

setupTestDB();

jest.setTimeout(10000);

describe('Trading Plan routes', () => {
  describe('POST /v1/trading-plan', () => {
    let newTradingPlan;

    beforeEach(() => {
      newTradingPlan = {
        maxTradesPerDay: 5,
        riskPercentPerTrade: 2.0,
        targetRiskRewardRatio: 1.5,
        preferredSessions: ['LONDON', 'NY'],
        stopLossDiscipline: 'ALWAYS',
      };
    });

    test('should return 201 and successfully create new trading plan if data is ok', async () => {
      await insertUsers([userOne]);

      const res = await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.CREATED);

      expect(res.body).toEqual({
        id: expect.anything(),
        userId: userOne._id.toHexString(),
        maxTradesPerDay: newTradingPlan.maxTradesPerDay,
        riskPercentPerTrade: newTradingPlan.riskPercentPerTrade,
        targetRiskRewardRatio: newTradingPlan.targetRiskRewardRatio,
        preferredSessions: newTradingPlan.preferredSessions,
        stopLossDiscipline: newTradingPlan.stopLossDiscipline,
      });

      const dbTradingPlan = await TradingPlan.findById(res.body.id);
      expect(dbTradingPlan).toBeDefined();
      expect(dbTradingPlan.userId.toString()).toBe(userOne._id.toString());
      expect(dbTradingPlan.maxTradesPerDay).toBe(newTradingPlan.maxTradesPerDay);
      expect(dbTradingPlan.riskPercentPerTrade).toBe(newTradingPlan.riskPercentPerTrade);
      expect(dbTradingPlan.targetRiskRewardRatio).toBe(newTradingPlan.targetRiskRewardRatio);
      expect(dbTradingPlan.preferredSessions.toObject()).toEqual(newTradingPlan.preferredSessions);
      expect(dbTradingPlan.stopLossDiscipline).toBe(newTradingPlan.stopLossDiscipline);
      expect(dbTradingPlan.id).toBeDefined();
    });

    test('should return 201 and successfully update existing trading plan', async () => {
      await insertUsers([userOne]);
      await insertTradingPlans([{ ...tradingPlanOne, userId: userOne._id }]);

      const updateData = {
        maxTradesPerDay: 10,
        riskPercentPerTrade: 3.0,
        targetRiskRewardRatio: 2.0,
        preferredSessions: ['ASIA'],
        stopLossDiscipline: 'FLEXIBLE',
      };

      const res = await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateData)
        .expect(httpStatus.CREATED);

      expect(res.body).toEqual({
        id: expect.anything(),
        userId: userOne._id.toHexString(),
        maxTradesPerDay: updateData.maxTradesPerDay,
        riskPercentPerTrade: updateData.riskPercentPerTrade,
        targetRiskRewardRatio: updateData.targetRiskRewardRatio,
        preferredSessions: updateData.preferredSessions,
        stopLossDiscipline: updateData.stopLossDiscipline,
      });

      const dbTradingPlan = await TradingPlan.findOne({ userId: userOne._id });
      expect(dbTradingPlan).toBeDefined();
      expect(dbTradingPlan.userId.toString()).toBe(userOne._id.toString());
      expect(dbTradingPlan.maxTradesPerDay).toBe(updateData.maxTradesPerDay);
      expect(dbTradingPlan.riskPercentPerTrade).toBe(updateData.riskPercentPerTrade);
      expect(dbTradingPlan.targetRiskRewardRatio).toBe(updateData.targetRiskRewardRatio);
      expect(dbTradingPlan.preferredSessions.toObject()).toEqual(updateData.preferredSessions);
      expect(dbTradingPlan.stopLossDiscipline).toBe(updateData.stopLossDiscipline);
      expect(dbTradingPlan.id).toBeDefined();
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).post('/v1/trading-plan').send(newTradingPlan).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 error if maxTradesPerDay is negative', async () => {
      await insertUsers([userOne]);
      newTradingPlan.maxTradesPerDay = -1;

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if riskPercentPerTrade is greater than 100', async () => {
      await insertUsers([userOne]);
      newTradingPlan.riskPercentPerTrade = 101;

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if targetRiskRewardRatio is negative', async () => {
      await insertUsers([userOne]);
      newTradingPlan.targetRiskRewardRatio = -1;

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if preferredSessions contains invalid session', async () => {
      await insertUsers([userOne]);
      newTradingPlan.preferredSessions = ['INVALID'];

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if stopLossDiscipline is invalid', async () => {
      await insertUsers([userOne]);
      newTradingPlan.stopLossDiscipline = 'INVALID';

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTradingPlan)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if required fields are missing', async () => {
      await insertUsers([userOne]);
      const incompletePlan = { maxTradesPerDay: 5 };

      await request(app)
        .post('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(incompletePlan)
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('GET /v1/trading-plan', () => {
    test('should return 200 and the trading plan if data is ok', async () => {
      await insertUsers([userOne]);
      await insertTradingPlans([{ ...tradingPlanOne, userId: userOne._id }]);

      const res = await request(app)
        .get('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        id: expect.anything(),
        userId: userOne._id.toHexString(),
        maxTradesPerDay: tradingPlanOne.maxTradesPerDay,
        riskPercentPerTrade: tradingPlanOne.riskPercentPerTrade,
        targetRiskRewardRatio: tradingPlanOne.targetRiskRewardRatio,
        preferredSessions: tradingPlanOne.preferredSessions,
        stopLossDiscipline: tradingPlanOne.stopLossDiscipline,
      });
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).get('/v1/trading-plan').send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 404 error if trading plan is not found', async () => {
      await insertUsers([userOne]);

      await request(app)
        .get('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('DELETE /v1/trading-plan', () => {
    test('should return 204 if data is ok', async () => {
      await insertUsers([userOne]);
      await insertTradingPlans([{ ...tradingPlanOne, userId: userOne._id }]);

      await request(app)
        .delete('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbTradingPlan = await TradingPlan.findOne({ userId: userOne._id });
      expect(dbTradingPlan).toBeNull();
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).delete('/v1/trading-plan').send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 404 error if trading plan is not found', async () => {
      await insertUsers([userOne]);

      await request(app)
        .delete('/v1/trading-plan')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });
});
