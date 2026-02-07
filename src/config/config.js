const dotenv = require('dotenv');
const path = require('path');
const Joi = require('joi');

dotenv.config({ path: path.join(__dirname, '../../.env') });

const envVarsSchema = Joi.object()
  .keys({
    NODE_ENV: Joi.string().valid('production', 'development', 'test').required(),
    PORT: Joi.number().default(3000),
    MONGODB_URL: Joi.string().required().description('Mongo DB url'),
    JWT_SECRET: Joi.string().required().description('JWT secret key'),
    JWT_ACCESS_EXPIRATION_MINUTES: Joi.number().default(30).description('minutes after which access tokens expire'),
    JWT_REFRESH_EXPIRATION_DAYS: Joi.number().default(30).description('days after which refresh tokens expire'),
    JWT_RESET_PASSWORD_EXPIRATION_MINUTES: Joi.number()
      .default(10)
      .description('minutes after which reset password token expires'),
    JWT_VERIFY_EMAIL_EXPIRATION_MINUTES: Joi.number()
      .default(10)
      .description('minutes after which verify email token expires'),
    SMTP_HOST: Joi.string().description('server that will send the emails'),
    SMTP_PORT: Joi.number().description('port to connect to the email server'),
    SMTP_SECURE: Joi.boolean().description('use TLS (true for port 465, false for other ports)'),
    SMTP_USERNAME: Joi.string().description('username for email server'),
    SMTP_PASSWORD: Joi.string().description('password for email server'),
    EMAIL_FROM: Joi.string().description('the from field in the emails sent by the app'),
    GOOGLE_CLIENT_ID: Joi.string().description('Google OAuth client ID'),
    GOOGLE_CLIENT_SECRET: Joi.string().description('Google OAuth client secret'),
    FRONTEND_URL: Joi.string().default('http://localhost:3000').description('Frontend URL for OAuth redirects'),
    MT5_API_URL: Joi.string().default('http://localhost:4000').description('MT5 Python service API URL'),
    MT5_API_KEY: Joi.string().default('your-secret-api-key-change-in-production').description('MT5 Python service API key'),
    MT5_ENCRYPTION_KEY: Joi.string().description('MT5 password encryption key (defaults to JWT_SECRET if not provided)'),
  })
  .unknown();

const { value: envVars, error } = envVarsSchema.prefs({ errors: { label: 'key' } }).validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

module.exports = {
  env: envVars.NODE_ENV,
  port: envVars.PORT,
  mongoose: {
    url: envVars.MONGODB_URL + (envVars.NODE_ENV === 'test' ? '-test' : ''),
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
    },
  },
  jwt: {
    secret: envVars.JWT_SECRET,
    accessExpirationMinutes: envVars.JWT_ACCESS_EXPIRATION_MINUTES,
    refreshExpirationDays: envVars.JWT_REFRESH_EXPIRATION_DAYS,
    resetPasswordExpirationMinutes: envVars.JWT_RESET_PASSWORD_EXPIRATION_MINUTES,
    verifyEmailExpirationMinutes: envVars.JWT_VERIFY_EMAIL_EXPIRATION_MINUTES,
  },
  email: {
    smtp: {
      host: envVars.SMTP_HOST,
      port: envVars.SMTP_PORT,
      secure: envVars.SMTP_SECURE === true || envVars.SMTP_PORT === 465, // true for 465, false for other ports
      auth:
        envVars.SMTP_USERNAME && envVars.SMTP_PASSWORD
          ? {
              user: envVars.SMTP_USERNAME,
              pass: envVars.SMTP_PASSWORD,
            }
          : undefined,
    },
    from: envVars.EMAIL_FROM,
  },
  google: {
    clientId: envVars.GOOGLE_CLIENT_ID,
    clientSecret: envVars.GOOGLE_CLIENT_SECRET,
  },
  frontend: {
    url: envVars.FRONTEND_URL,
  },
  mt5: {
    apiUrl: envVars.MT5_API_URL,
    apiKey: envVars.MT5_API_KEY,
    encryptionKey: envVars.MT5_ENCRYPTION_KEY,
  },
};
