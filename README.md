# Zentra Backend - Trading Psychology Engine

A boilerplate/starter project for quickly building RESTful APIs using Node.js, Express, and Mongoose.

By running a single command, you will get a production-ready Node.js app installed and fully configured on your machine. The app comes with many built-in features, such as authentication using JWT, request validation, unit and integration tests, continuous integration, docker support, API documentation, pagination, etc. For more details, check the features list below.

## Quick Start

To create a project, simply run:

```bash
npx create-nodejs-express-app <project-name>
```

Or

```bash
npm init nodejs-express-app <project-name>
```

## Manual Installation

If you would still prefer to do the installation manually, follow these steps:

Clone the repo:

```bash
git clone --depth 1 https://github.com/hagopj13/node-express-boilerplate.git
cd node-express-boilerplate
npx rimraf ./.git
```

Install the dependencies:

```bash
yarn install
```

Set the environment variables:

```bash
cp .env.example .env

# open .env and modify the environment variables (if needed)
```

## Table of Contents

- [RESTful API Node Server Boilerplate](#restful-api-node-server-boilerplate)
  - [Quick Start](#quick-start)
  - [Manual Installation](#manual-installation)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Commands](#commands)
  - [Environment Variables](#environment-variables)
  - [Project Structure](#project-structure)
  - [API Documentation](#api-documentation)
    - [API Endpoints](#api-endpoints)
  - [Error Handling](#error-handling)
  - [Validation](#validation)
  - [Authentication](#authentication)
  - [Authorization](#authorization)
  - [Logging](#logging)
  - [Custom Mongoose Plugins](#custom-mongoose-plugins)
    - [toJSON](#tojson)
    - [paginate](#paginate)
  - [Linting](#linting)
  - [Contributing](#contributing)
  - [Inspirations](#inspirations)
  - [License](#license)

## Features

- **NoSQL database**: [MongoDB](https://www.mongodb.com) object data modeling using [Mongoose](https://mongoosejs.com)
- **Authentication and authorization**: using [passport](http://www.passportjs.org)
- **Validation**: request data validation using [Joi](https://github.com/hapijs/joi)
- **Logging**: using [winston](https://github.com/winstonjs/winston) and [morgan](https://github.com/expressjs/morgan)
- **Testing**: unit and integration tests using [Jest](https://jestjs.io)
- **Error handling**: centralized error handling mechanism
- **API documentation**: with [swagger-jsdoc](https://github.com/Surnet/swagger-jsdoc) and [swagger-ui-express](https://github.com/scottie1984/swagger-ui-express)
- **Process management**: advanced production process management using [PM2](https://pm2.keymetrics.io)
- **Dependency management**: with [Yarn](https://yarnpkg.com)
- **Environment variables**: using [dotenv](https://github.com/motdotla/dotenv) and [cross-env](https://github.com/kentcdodds/cross-env#readme)
- **Security**: set security HTTP headers using [helmet](https://helmetjs.github.io)
- **Santizing**: sanitize request data against xss and query injection
- **CORS**: Cross-Origin Resource-Sharing enabled using [cors](https://github.com/expressjs/cors)
- **Compression**: gzip compression with [compression](https://github.com/expressjs/compression)
- **CI**: continuous integration with [Travis CI](https://travis-ci.org)
- **Docker support**
- **Code coverage**: using [coveralls](https://coveralls.io)
- **Code quality**: with [Codacy](https://www.codacy.com)
- **Git hooks**: with [husky](https://github.com/typicode/husky) and [lint-staged](https://github.com/okonet/lint-staged)
- **Linting**: with [ESLint](https://eslint.org) and [Prettier](https://prettier.io)
- **Editor config**: consistent editor configuration using [EditorConfig](https://editorconfig.org)

## Zentra Overview

This backend powers a trading psychology assistant that analyzes a trader's recent behavior against their self-defined plan.

- Psychological States: `STABLE`, `OVEREXTENDED`, `HESITANT`, `AGGRESSIVE`
- Plan inputs: max trades/day, risk % per trade, target R:R, preferred sessions (`LONDON`, `NY`, `ASIA`), stop-loss discipline (`ALWAYS`, `FLEXIBLE`)
- Core outputs:
  - Current State: state, confidence, planAdherence, indicators, recommendations
  - Session Forecast: predictedBias, riskLevel, forecast, basedOnState
  - Performance Insights: positive + constructive insights with stats
  - Dashboard Summary: quick stats, trends, alerts aligned to current state

### MT5 Integration

The backend supports integration with MetaTrader 5 (MT5) accounts for automatic trade data synchronization. This feature allows users to:

- Connect their MT5 trading account securely
- Automatically sync trade history from MT5
- Import trades directly into the system for analysis

**Architecture**: The MT5 integration uses a separate Python microservice (`mt5-service/`) that handles direct communication with the MT5 API. The Node.js backend communicates with this Python service via REST API.

**Security**: MT5 passwords are encrypted using AES-256-CBC encryption before storage, following the same pattern as user password hashing (automatic encryption on save via Mongoose pre-save hook).

**Single Account Restriction**: Users can only connect one MT5 account at a time. Attempting to connect a different account while one is already connected returns a 409 Conflict error. Users must disconnect the current account before connecting a new one.

**Trade Source Tracking**: All trades are tagged with a `source` field:

- `source.type: 'manual'` - Trades created via manual import or the API
- `source.type: 'mt5'` - Trades synced from MT5
- `source.mt5AccountId` - The MT5 account ID for MT5-sourced trades

**Disconnect Cleanup**: When disconnecting an MT5 account:

- All trades with matching `source.mt5AccountId` are deleted
- All BehaviorHeatmapHistory records for the user are deleted
- All StabilityTrendHistory records for the user are deleted
- MT5 account credentials are cleared

**Setup**:

1. Deploy the Python MT5 service (see `mt5-service/README.md`)
2. Configure `MT5_API_URL` and `MT5_API_KEY` environment variables
3. Users can connect their MT5 accounts via the `/v1/mt5/connect` endpoint
4. Trades can be synced automatically using `/v1/mt5/sync`

## Psychological State & Analysis Logic

### Data inputs

- Trade fields used:
  - `entryTime`: Trade entry timestamp
  - `exitTime`: Trade exit timestamp
  - `profitLoss`: Profit or loss amount (can be negative)
  - `riskPercentUsed`: Risk percentage used (min: 0, nullable - excluded from calculations if null)
  - `riskRewardAchieved`: Risk-reward ratio achieved (nullable - excluded from calculations if null)
  - `targetPercentAchieved`: Percentage of target achieved (nullable - excluded from calculations if null, can be negative, e.g., -50 means trade went 50% against target)
  - `exitedEarly`: Boolean indicating if trade was exited early
  - `stopLossHit`: Boolean indicating if stop loss was hit
  - `session`: Trading session (`LONDON`, `NY`, `ASIA`)
  - `mt5DealId`: MT5 deal ID (optional, nullable)
  - `mt5Symbol`: MT5 symbol (optional, nullable)
  - `source`: Trade source tracking (object)
    - `source.type`: 'manual' or 'mt5' (defaults to 'manual')
    - `source.mt5AccountId`: MT5 account ID (for MT5 trades)
  - `notes`: Additional notes (optional)
- Trading Plan fields used: `maxTradesPerDay`, `riskPercentPerTrade`, `targetRiskRewardRatio`, `preferredSessions` (and optionally `stopLossDiscipline`)

### Psychological state (analyzePsychologicalState)

1. Scope: up to the last 10 trades are analyzed.
2. Metrics:
   - `winRate = wins / totalTrades`
   - `avgRiskUsed = avg(riskPercentUsed)` - only calculated from trades with non-null `riskPercentUsed`
   - `avgRR = avg(riskRewardAchieved)` - only calculated from trades with non-null `riskRewardAchieved`
   - `medianTargetPct = median(targetPercentAchieved)` - only calculated from trades with non-null `targetPercentAchieved`
   - `earlyExits = count(exitedEarly || (targetPercentAchieved != null && targetPercentAchieved < 50))`
   - `stopLossHits = count(stopLossHit)`
   - `outsideSession = count(!preferredSessions.includes(session))`
   - `riskBreaches = count(riskPercentUsed != null && riskPercentUsed > plan.riskPercentPerTrade * 1.5)` - only counts trades with non-null `riskPercentUsed`
   - Trades/day: group by date; `exceededDays = count(days where trades > maxTradesPerDay)`
   - `riskSpike = lastRisk > recentAvgRisk * 1.5 || lastRisk > plan.riskPercentPerTrade * 1.5` - only considers trades with non-null `riskPercentUsed`
   - `nearTargetHits = count(targetPercentAchieved != null && targetPercentAchieved >= 80)` - only counts trades with non-null `targetPercentAchieved`
3. Plan adherence (0–100): average of
   - `1 - riskBreaches/totalTrades`
   - `1 - outsideSession/totalTrades`
   - `1 - exceededDays/daysWithTrades`
   - `min(1, nearTargetHits/totalTrades)`
4. State determination:
   - OVEREXTENDED: `exceededDays > 0` OR `outsideSession/totalTrades >= 0.25`
   - AGGRESSIVE: `riskSpike` OR `riskBreaches/totalTrades >= 0.3` OR `stopLossHits/totalTrades >= 0.4`
   - HESITANT: `earlyExits/totalTrades >= 0.4` OR `avgTargetAchieved < plan.targetRiskRewardRatio * 50`
   - STABLE: otherwise
   - Indicators and recommendations are populated to explain rationale.
5. Confidence (10–95):
   - `confidenceBase = planAdherence*0.6 + (winRate*100)*0.2 + max(0, avgRR / max(1, targetRiskRewardRatio))*20`
   - Clamp to 10–95 and round.
6. No data fallback: If no trades or no plan, returns STABLE with defaults (confidence 50, adherence 50) and an informative indicator.

### State history (analyzeStateHistory)

- Trades are sorted by `entryTime` ascending; slide a window of up to 5 recent trades per step.
- A history entry is added when the state changes or when `|confidence - lastConfidence| > 15`.
- Summary includes: `totalChanges`, `mostCommonState`, `averageConfidence`, and `volatility` (std dev of confidences, normalized and rounded).

### Session forecast (analyzeSessionForecast)

- Inputs: last 20 trades for the session, the plan, and current state.
- Heuristics:
  - Recent loss streak (last 3 trades ≤ 0) → bias: Revenge trading risk; `riskLevel = HIGH`.
  - `avgRisk > riskPercentPerTrade * 1.25` → bias: Risk escalation; `riskLevel = HIGH`.
  - `outsideSessionTrades/total >= 0.2` → bias: Session drift; at least `riskLevel = MEDIUM`.
- Forecast: `NEGATIVE` if `riskLevel = HIGH`, `POSITIVE` if `LOW`, else `NEUTRAL`.
- Returns recommendations tied to detected biases and the `basedOnState` reference.

### Performance insights (analyzePerformanceInsights)

- Stats: `winRate`, `avgRiskReward`, `planAdherence` (computed from risk breaches and outside-session ratios), `tradesThisWeek`.
- Positive insight if `planAdherence >= 70` else if `winRate >= 60`.
- Constructive insight if `earlyExits/total >= 0.3` else if `planAdherence < 60`.
- Guarantees at least one POSITIVE and one CONSTRUCTIVE item; recommendations summarize constructive items.

### Dashboard metrics (dashboard.service)

- Summary stats: totals, win rate, total PnL, average R:R (calculated only from trades with non-null `riskRewardAchieved`), best/worst trades.
- Trends: split trades into halves; compare PnL, winRate, and average risk (UP/DOWN/STABLE). Risk trend calculated only from trades with non-null `riskPercentUsed`.
- Alerts:
  - Win rate ≥ 0.7 → success; ≤ 0.3 → warning.
  - Avg risk > 3 → warning; < 1 → info (calculated only from trades with non-null `riskPercentUsed`).
  - Recent win-rate deviates from overall by ±0.2 → success/warning.
  - State-specific alerts for AGGRESSIVE, HESITANT, OVEREXTENDED.

**Null Value Handling**: All calculations exclude null values. For example, if 5 trades have `riskPercentUsed` values [2.0, null, 1.5, null, 2.5], the average is calculated as `(2.0 + 1.5 + 2.5) / 3 = 2.0`, not `(2.0 + 0 + 1.5 + 0 + 2.5) / 5 = 1.2`. This ensures metrics reflect only available data and aren't skewed by missing values.

### Logging & observability

- Each analysis entry point logs start/end and key metrics using `src/config/logger`:
  - State: start, default fallback, computed state + metrics.
  - Session forecast: start, number of trades found, forecast result.
  - Insights: start, trades found, count of generated insights.
  - History: start, trades found, records generated.
- Enable verbose logging in development to trace decision thresholds when debugging.

## Commands

Running locally:

```bash
yarn dev
```

Running in production:

```bash
yarn start
```

Testing:

```bash
# run all tests
yarn test

# run all tests in watch mode
yarn test:watch

# run test coverage
yarn coverage
```

Docker:

```bash
# run docker container in development mode
yarn docker:dev

# run docker container in production mode
yarn docker:prod

# run all tests in a docker container
yarn docker:test
```

Linting:

```bash
# run ESLint
yarn lint

# fix ESLint errors
yarn lint:fix

# run prettier
yarn prettier

# fix prettier errors
yarn prettier:fix
```

## Environment Variables

The environment variables can be found and modified in the `.env` file. They come with these default values:

```bash
# Port number
PORT=3000

# URL of the Mongo DB
MONGODB_URL=mongodb://127.0.0.1:27017/node-boilerplate

# JWT
# JWT secret key
JWT_SECRET=thisisasamplesecret
# Number of minutes after which an access token expires
JWT_ACCESS_EXPIRATION_MINUTES=30
# Number of days after which a refresh token expires
JWT_REFRESH_EXPIRATION_DAYS=30

# SMTP configuration options for the email service
# For testing, you can use a fake SMTP service like Ethereal: https://ethereal.email/create
SMTP_HOST=email-server
SMTP_PORT=587
SMTP_USERNAME=email-server-username
SMTP_PASSWORD=email-server-password
EMAIL_FROM=support@yourapp.com

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Frontend URL for OAuth redirects
FRONTEND_URL=http://localhost:3000

# MT5 Python Service Integration
MT5_API_URL=http://localhost:4000
MT5_API_KEY=your-secret-api-key-change-in-production
MT5_ENCRYPTION_KEY=your-mt5-encryption-key (optional, defaults to JWT_SECRET)
```

## Project Structure

```
src\
 |--config\         # Environment variables and configuration related things
 |--controllers\    # Route controllers (controller layer)
 |--docs\           # Swagger files
 |--middlewares\    # Custom express middlewares
 |--models\         # Mongoose models (data layer)
 |--routes\         # Routes
 |--services\       # Business logic (service layer)
 |--utils\          # Utility classes and functions
 |--validations\    # Request data validation schemas
 |--app.js          # Express app
 |--index.js        # App entry point
```

## API Documentation

To view the list of available APIs and their specifications, run the server and go to `http://localhost:3000/v1/docs` in your browser. This documentation page is automatically generated using the [swagger](https://swagger.io/) definitions written as comments in the route files.

### API Endpoints

List of available routes:

**Auth routes**:\
`POST /v1/auth/register` - register\
`POST /v1/auth/login` - login\
`GET /v1/auth/google` - initiate Google OAuth\
`GET /v1/auth/google/callback` - Google OAuth callback\
`POST /v1/auth/refresh-tokens` - refresh auth tokens\
`POST /v1/auth/forgot-password` - send reset password email\
`POST /v1/auth/reset-password` - reset password\
`POST /v1/auth/send-verification-email` - send verification email\
`POST /v1/auth/verify-email` - verify email

**User routes**:\
`POST /v1/users` - create a user\
`GET /v1/users` - get all users\
`GET /v1/users/:userId` - get user\
`PATCH /v1/users/:userId` - update user\
`DELETE /v1/users/:userId` - delete user

**Trading Plan**:\
`POST /v1/trading-plan` - create/update plan (maxTradesPerDay, riskPercentPerTrade, targetRiskRewardRatio, preferredSessions, stopLossDiscipline)\
`GET /v1/trading-plan` - get current plan\
`DELETE /v1/trading-plan` - reset plan

**Trades** (requires trading plan):\
`POST /v1/trades` - create trade (entryTime, exitTime, profitLoss, session, stopLossHit, exitedEarly, riskPercentUsed*, riskRewardAchieved*, targetPercentAchieved\*, notes, mt5DealId, mt5Symbol)\
`POST /v1/trades/bulk` - import multiple trades\
`GET /v1/trades` - list trades (filters + pagination)\
`GET /v1/trades/:id` - get trade\
`PUT /v1/trades/:id` - update trade\
`DELETE /v1/trades/:id` - delete trade

Note: Fields marked with \* are optional and nullable. When null, they are excluded from all calculations (averages, metrics, state analysis, etc.). `targetPercentAchieved` can be negative to represent trades that went against the target direction. `mt5DealId` and `mt5Symbol` are optional fields for MT5 integration.

**Analysis** (requires trading plan):\
`GET /v1/analysis/state` - current state { state, confidence, planAdherence, analyzedTradeCount, indicators[], recommendations[] }\
`GET /v1/analysis/forecast?session=LONDON|NY|ASIA` - session forecast { predictedBias, riskLevel, forecast, basedOnState, recommendations[] }\
`GET /v1/analysis/insights?period=WEEK|MONTH|QUARTER|YEAR` - insights { insights[], stats, recommendations[] }\
`GET /v1/analysis/history?startDate&endDate&limit` - history { history[], summary }

**Dashboard** (requires trading plan):\
`GET /v1/dashboard?period=MONTH` - full dashboard (summary, psychologicalState, performance, insights, recentTrades)\
`GET /v1/dashboard/summary?period=MONTH` - quick summary (quickStats, trends, alerts)

**MT5 Integration**:\
`POST /v1/mt5/connect` - connect MetaTrader 5 account (accountId, server, password) - returns 409 if different account already connected\
`POST /v1/mt5/sync` - sync trades from MT5 account (optional fromDate, toDate automatically set to current time) - **requires trading plan**\
`GET /v1/mt5/status` - get MT5 connection status - no trading plan required\
`DELETE /v1/mt5/disconnect` - disconnect MT5 account and delete all related trades/history

**MT5 Trade Data**: When syncing trades from MT5, the Python service returns trade data with the following fields:

- `entryTime`, `exitTime`, `profitLoss`, `session`, `stopLossHit`, `exitedEarly` (required)
- `riskPercentUsed`, `riskRewardAchieved`, `targetPercentAchieved` (nullable - may be null if not calculable)
- `mt5DealId`, `mt5Symbol` (included for MT5 trade tracking)
- `notes` (auto-generated with MT5 account info)

All nullable fields are properly handled in calculations - null values are excluded from averages and metrics, ensuring accurate analysis even when some trade data is incomplete.

## Error Handling

The app has a centralized error handling mechanism.

Controllers should try to catch the errors and forward them to the error handling middleware (by calling `next(error)`). For convenience, you can also wrap the controller inside the catchAsync utility wrapper, which forwards the error.

```javascript
const catchAsync = require('../utils/catchAsync');

const controller = catchAsync(async (req, res) => {
  // this error will be forwarded to the error handling middleware
  throw new Error('Something wrong happened');
});
```

The error handling middleware sends an error response, which has the following format:

```json
{
  "code": 404,
  "message": "Not found"
}
```

When running in development mode, the error response also contains the error stack.

The app has a utility ApiError class to which you can attach a response code and a message, and then throw it from anywhere (catchAsync will catch it).

For example, if you are trying to get a user from the DB who is not found, and you want to send a 404 error, the code should look something like:

```javascript
const httpStatus = require('http-status');
const ApiError = require('../utils/ApiError');
const User = require('../models/User');

const getUser = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
};
```

## Validation

Request data is validated using [Joi](https://joi.dev/). Check the [documentation](https://joi.dev/api/) for more details on how to write Joi validation schemas.

The validation schemas are defined in the `src/validations` directory and are used in the routes by providing them as parameters to the `validate` middleware.

```javascript
const express = require('express');
const validate = require('../../middlewares/validate');
const userValidation = require('../../validations/user.validation');
const userController = require('../../controllers/user.controller');

const router = express.Router();

router.post('/users', validate(userValidation.createUser), userController.createUser);
```

## Authentication

To require authentication for certain routes, you can use the `auth` middleware.

```javascript
const express = require('express');
const auth = require('../../middlewares/auth');
const userController = require('../../controllers/user.controller');

const router = express.Router();

router.post('/users', auth(), userController.createUser);
```

These routes require a valid JWT access token in the Authorization request header using the Bearer schema. If the request does not contain a valid access token, an Unauthorized (401) error is thrown.

**Generating Access Tokens**:

An access token can be generated by making a successful call to the register (`POST /v1/auth/register`) or login (`POST /v1/auth/login`) endpoints. The response of these endpoints also contains refresh tokens (explained below).

An access token is valid for 30 minutes. You can modify this expiration time by changing the `JWT_ACCESS_EXPIRATION_MINUTES` environment variable in the .env file.

**Refreshing Access Tokens**:

After the access token expires, a new access token can be generated, by making a call to the refresh token endpoint (`POST /v1/auth/refresh-tokens`) and sending along a valid refresh token in the request body. This call returns a new access token and a new refresh token.

A refresh token is valid for 30 days. You can modify this expiration time by changing the `JWT_REFRESH_EXPIRATION_DAYS` environment variable in the .env file.

**Google OAuth Authentication**:

The app supports Google OAuth authentication. To set it up:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" and create OAuth 2.0 Client IDs
5. Set the authorized redirect URI to: `http://localhost:3000/v1/auth/google/callback` (or your domain)
6. Copy the Client ID and Client Secret to your `.env` file

The Google OAuth flow works as follows:

- User visits `/v1/auth/google` to initiate Google sign-in
- User is redirected to Google for authentication
- After successful authentication, Google redirects to `/v1/auth/google/callback`
- The callback generates JWT tokens and redirects to your frontend with the tokens

## Trading Plan Requirement

Most trading-related routes require users to have a trading plan before accessing them. The `requireTradingPlan` middleware enforces this requirement.

```javascript
const express = require('express');
const auth = require('../../middlewares/auth');
const requireTradingPlan = require('../../middlewares/requireTradingPlan');
const tradeController = require('../../controllers/trade.controller');

const router = express.Router();

router.post('/trades', auth(), requireTradingPlan, tradeController.createTrade);
```

The middleware should be used **after** the `auth()` middleware. If a user attempts to access a protected route without a trading plan, a Forbidden (403) error is returned with the message: "Trading plan required. Please create a trading plan before accessing this resource."

**Routes that require a trading plan:**

- All trade routes (create, read, update, delete)
- All analysis routes (state, forecast, insights, history)
- All dashboard routes
- MT5 sync route (to import trades)

**Routes that do NOT require a trading plan:**

- Trading plan routes (create, get, delete) - users need to be able to create their plan
- MT5 connect, status, disconnect routes - account management only
- Auth routes - public access

## Authorization

The `auth` middleware can also be used to require certain rights/permissions to access a route.

```javascript
const express = require('express');
const auth = require('../../middlewares/auth');
const userController = require('../../controllers/user.controller');

const router = express.Router();

router.post('/users', auth('manageUsers'), userController.createUser);
```

In the example above, an authenticated user can access this route only if that user has the `manageUsers` permission.

The permissions are role-based. You can view the permissions/rights of each role in the `src/config/roles.js` file.

If the user making the request does not have the required permissions to access this route, a Forbidden (403) error is thrown.

## Logging

Import the logger from `src/config/logger.js`. It is using the [Winston](https://github.com/winstonjs/winston) logging library.

Logging should be done according to the following severity levels (ascending order from most important to least important):

```javascript
const logger = require('<path to src>/config/logger');

logger.error('message'); // level 0
logger.warn('message'); // level 1
logger.info('message'); // level 2
logger.http('message'); // level 3
logger.verbose('message'); // level 4
logger.debug('message'); // level 5
```

In development mode, log messages of all severity levels will be printed to the console.

In production mode, only `info`, `warn`, and `error` logs will be printed to the console.\
It is up to the server (or process manager) to actually read them from the console and store them in log files.\
This app uses pm2 in production mode, which is already configured to store the logs in log files.

Note: API request information (request url, response code, timestamp, etc.) are also automatically logged (using [morgan](https://github.com/expressjs/morgan)).

## Custom Mongoose Plugins

The app also contains 2 custom mongoose plugins that you can attach to any mongoose model schema. You can find the plugins in `src/models/plugins`.

```javascript
const mongoose = require('mongoose');
const { toJSON, paginate } = require('./plugins');

const userSchema = mongoose.Schema(
  {
    /* schema definition here */
  },
  { timestamps: true }
);

userSchema.plugin(toJSON);
userSchema.plugin(paginate);

const User = mongoose.model('User', userSchema);
```

### toJSON

The toJSON plugin applies the following changes in the toJSON transform call:

- removes \_\_v, createdAt, updatedAt, and any schema path that has private: true
- replaces \_id with id

### paginate

The paginate plugin adds the `paginate` static method to the mongoose schema.

Adding this plugin to the `User` model schema will allow you to do the following:

```javascript
const queryUsers = async (filter, options) => {
  const users = await User.paginate(filter, options);
  return users;
};
```

The `filter` param is a regular mongo filter.

The `options` param can have the following (optional) fields:

```javascript
const options = {
  sortBy: 'name:desc', // sort order
  limit: 5, // maximum results per page
  page: 2, // page number
};
```

The plugin also supports sorting by multiple criteria (separated by a comma): `sortBy: name:desc,role:asc`

The `paginate` method returns a Promise, which fulfills with an object having the following properties:

```json
{
  "results": [],
  "page": 2,
  "limit": 5,
  "totalPages": 10,
  "totalResults": 48
}
```

## Linting

Linting is done using [ESLint](https://eslint.org/) and [Prettier](https://prettier.io).

In this app, ESLint is configured to follow the [Airbnb JavaScript style guide](https://github.com/airbnb/javascript/tree/master/packages/eslint-config-airbnb-base) with some modifications. It also extends [eslint-config-prettier](https://github.com/prettier/eslint-config-prettier) to turn off all rules that are unnecessary or might conflict with Prettier.

To modify the ESLint configuration, update the `.eslintrc.json` file. To modify the Prettier configuration, update the `.prettierrc.json` file.

To prevent a certain file or directory from being linted, add it to `.eslintignore` and `.prettierignore`.

To maintain a consistent coding style across different IDEs, the project contains `.editorconfig`

## Contributing

Contributions are more than welcome! Please check out the [contributing guide](CONTRIBUTING.md).

## Inspirations

- [danielfsousa/express-rest-es2017-boilerplate](https://github.com/danielfsousa/express-rest-es2017-boilerplate)
- [madhums/node-express-mongoose](https://github.com/madhums/node-express-mongoose)
- [kunalkapadia/express-mongoose-es6-rest-api](https://github.com/kunalkapadia/express-mongoose-es6-rest-api)

## License

[MIT](LICENSE)
