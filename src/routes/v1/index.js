const express = require('express');
const authRoute = require('./auth.route');
const userRoute = require('./user.route');
const tradingPlanRoute = require('./tradingPlan.route');
const tradeRoute = require('./trade.route');
const analysisRoute = require('./analysis.route');
const dashboardRoute = require('./dashboard.route');
const healthRoute = require('./health.route');
const docsRoute = require('./docs.route');
const mt5Route = require('./mt5.route');
const config = require('../../config/config');

const router = express.Router();

const defaultRoutes = [
  {
    path: '/auth',
    route: authRoute,
  },
  {
    path: '/users',
    route: userRoute,
  },
  {
    path: '/trading-plan',
    route: tradingPlanRoute,
  },
  {
    path: '/trades',
    route: tradeRoute,
  },
  {
    path: '/analysis',
    route: analysisRoute,
  },
  {
    path: '/dashboard',
    route: dashboardRoute,
  },
  {
    path: '/mt5',
    route: mt5Route,
  },
  {
    path: '/health',
    route: healthRoute,
  },
];

const devRoutes = [
  // routes available only in development mode
  {
    path: '/docs',
    route: docsRoute,
  },
];

defaultRoutes.forEach((route) => {
  router.use(route.path, route.route);
});

/* istanbul ignore next */
if (config.env === 'development') {
  devRoutes.forEach((route) => {
    router.use(route.path, route.route);
  });
}

module.exports = router;
