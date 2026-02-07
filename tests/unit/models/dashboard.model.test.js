const mongoose = require('mongoose');
const { Dashboard } = require('../../../src/models');
const { PsychologicalState } = require('../../../src/models/enums');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('Dashboard model', () => {
  let dashboardData;

  beforeEach(() => {
    dashboardData = {
      userId: mongoose.Types.ObjectId(),
      user: {
        id: mongoose.Types.ObjectId(),
        name: 'John Doe',
      },
      brainHero: {
        state: PsychologicalState.CONFIDENT,
        stateAnalysis: mongoose.Types.ObjectId(),
      },
      sessionForecast: mongoose.Types.ObjectId(),
      performanceSnapshot: mongoose.Types.ObjectId(),
      recentTrades: [mongoose.Types.ObjectId(), mongoose.Types.ObjectId()],
      lastUpdated: new Date(),
    };
  });

  test('should create dashboard successfully', async () => {
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard._id).toBeDefined();
    expect(savedDashboard.userId.toString()).toBe(dashboardData.userId.toString());
    expect(savedDashboard.user.id.toString()).toBe(dashboardData.user.id.toString());
    expect(savedDashboard.user.name).toBe(dashboardData.user.name);
    expect(savedDashboard.brainHero.state).toBe(dashboardData.brainHero.state);
    expect(savedDashboard.brainHero.stateAnalysis.toString()).toBe(dashboardData.brainHero.stateAnalysis.toString());
    expect(savedDashboard.sessionForecast.toString()).toBe(dashboardData.sessionForecast.toString());
    expect(savedDashboard.performanceSnapshot.toString()).toBe(dashboardData.performanceSnapshot.toString());
    expect(savedDashboard.recentTrades).toHaveLength(2);
    expect(savedDashboard.lastUpdated).toEqual(dashboardData.lastUpdated);
    expect(savedDashboard.createdAt).toBeDefined();
    expect(savedDashboard.updatedAt).toBeDefined();
  });

  test('should require userId', async () => {
    delete dashboardData.userId;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require user.id', async () => {
    delete dashboardData.user.id;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require user.name', async () => {
    delete dashboardData.user.name;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require brainHero.state', async () => {
    delete dashboardData.brainHero.state;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require brainHero.stateAnalysis', async () => {
    delete dashboardData.brainHero.stateAnalysis;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require sessionForecast', async () => {
    delete dashboardData.sessionForecast;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should require performanceSnapshot', async () => {
    delete dashboardData.performanceSnapshot;
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should validate brainHero.state enum values', async () => {
    dashboardData.brainHero.state = 'INVALID_STATE';
    const dashboard = new Dashboard(dashboardData);

    await expect(dashboard.save()).rejects.toThrow();
  });

  test('should allow all psychological states', async () => {
    Object.values(PsychologicalState).forEach(async (state) => {
      dashboardData.brainHero.state = state;
      const dashboard = new Dashboard(dashboardData);
      const savedDashboard = await dashboard.save();

      expect(savedDashboard.brainHero.state).toBe(state);
    });
  });

  test('should allow empty recentTrades array', async () => {
    dashboardData.recentTrades = [];
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.recentTrades).toEqual([]);
  });

  test('should handle multiple recent trades', async () => {
    dashboardData.recentTrades = [
      mongoose.Types.ObjectId(),
      mongoose.Types.ObjectId(),
      mongoose.Types.ObjectId(),
      mongoose.Types.ObjectId(),
    ];

    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.recentTrades).toHaveLength(4);
  });

  test('should handle optional lastUpdated field', async () => {
    delete dashboardData.lastUpdated;
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.lastUpdated).toBeUndefined();
  });

  test('should handle user name trimming', async () => {
    dashboardData.user.name = '  John Doe  ';
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.user.name).toBe('John Doe');
  });

  test('should have toJSON plugin applied', async () => {
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();
    const json = savedDashboard.toJSON();

    expect(json).not.toHaveProperty('_id');
    expect(json).not.toHaveProperty('__v');
    expect(json).toHaveProperty('id');
    expect(json.id).toBe(savedDashboard._id.toString());
  });

  test('should have proper indexes', async () => {
    const indexes = Dashboard.collection.getIndexes();
    expect(indexes).toHaveProperty('userId_1');
    expect(indexes).toHaveProperty('brainHero.state_1');
  });

  test('should handle complex nested user object', async () => {
    dashboardData.user = {
      id: mongoose.Types.ObjectId(),
      name: 'Jane Smith',
    };

    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.user.id.toString()).toBe(dashboardData.user.id.toString());
    expect(savedDashboard.user.name).toBe(dashboardData.user.name);
  });

  test('should handle complex nested brainHero object', async () => {
    dashboardData.brainHero = {
      state: PsychologicalState.ANXIOUS,
      stateAnalysis: mongoose.Types.ObjectId(),
    };

    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.brainHero.state).toBe(PsychologicalState.ANXIOUS);
    expect(savedDashboard.brainHero.stateAnalysis.toString()).toBe(dashboardData.brainHero.stateAnalysis.toString());
  });

  test('should handle ObjectId references correctly', async () => {
    const stateAnalysisId = mongoose.Types.ObjectId();
    const sessionForecastId = mongoose.Types.ObjectId();
    const performanceSnapshotId = mongoose.Types.ObjectId();
    const tradeId1 = mongoose.Types.ObjectId();
    const tradeId2 = mongoose.Types.ObjectId();

    dashboardData.brainHero.stateAnalysis = stateAnalysisId;
    dashboardData.sessionForecast = sessionForecastId;
    dashboardData.performanceSnapshot = performanceSnapshotId;
    dashboardData.recentTrades = [tradeId1, tradeId2];

    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.brainHero.stateAnalysis.toString()).toBe(stateAnalysisId.toString());
    expect(savedDashboard.sessionForecast.toString()).toBe(sessionForecastId.toString());
    expect(savedDashboard.performanceSnapshot.toString()).toBe(performanceSnapshotId.toString());
    expect(savedDashboard.recentTrades[0].toString()).toBe(tradeId1.toString());
    expect(savedDashboard.recentTrades[1].toString()).toBe(tradeId2.toString());
  });

  test('should handle timestamps correctly', async () => {
    const dashboard = new Dashboard(dashboardData);
    const savedDashboard = await dashboard.save();

    expect(savedDashboard.createdAt).toBeInstanceOf(Date);
    expect(savedDashboard.updatedAt).toBeInstanceOf(Date);
    expect(savedDashboard.createdAt.getTime()).toBeLessThanOrEqual(Date.now());
    expect(savedDashboard.updatedAt.getTime()).toBeLessThanOrEqual(Date.now());
  });
});
