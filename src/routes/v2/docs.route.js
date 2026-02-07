const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const swaggerDefinition = require('../../docs/swaggerDefV2');
const logger = require('../../config/logger');

const router = express.Router();

const specs = swaggerJsdoc({
  swaggerDefinition,
  apis: ['src/docs/*.yml', 'src/routes/v2/*.js'],
});

// Serve raw OpenAPI JSON spec
router.get('/openapi.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(specs);
});

// Serve Swagger UI static assets
router.use('/', swaggerUi.serve);

// Setup Swagger UI with custom options
router.get(
  '/',
  swaggerUi.setup(specs, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Zentra V2 API Documentation',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
    },
  })
);

// Log when docs route is accessed
router.use((req, res, next) => {
  logger.info(`[Swagger Docs V2] ${req.method} ${req.path} - ${req.ip}`);
  next();
});

module.exports = router;
