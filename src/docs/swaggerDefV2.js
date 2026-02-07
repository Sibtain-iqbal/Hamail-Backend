const { version } = require('../../package.json');
const config = require('../config/config');

const swaggerDefV2 = {
  openapi: '3.0.0',
  info: {
    title: 'Zentra V2 API Documentation',
    version,
    description: 'Zentra V2 psychological trading analysis endpoints',
  },
  servers: [
    {
      url: `http://localhost:${config.port}/v2`,
      description: 'Development server',
    },
  ],
};

module.exports = swaggerDefV2;
