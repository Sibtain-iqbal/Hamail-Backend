const nodemailer = require('nodemailer');
const config = require('../config/config');
const logger = require('../config/logger');

logger.info('Initializing email service...', {
  host: (config.email.smtp && config.email.smtp.host) || 'not configured',
  port: (config.email.smtp && config.email.smtp.port) || 'not configured',
  from: config.email.from || 'not configured',
});

const transport = nodemailer.createTransport(config.email.smtp);
/* istanbul ignore next */
if (config.env !== 'test') {
  transport
    .verify()
    .then(() => {
      logger.info('Successfully connected to email server', {
        host: (config.email.smtp && config.email.smtp.host) || 'unknown',
        port: (config.email.smtp && config.email.smtp.port) || 'unknown',
      });
    })
    .catch((error) => {
      logger.warn('Unable to connect to email server. Make sure you have configured the SMTP options in .env', {
        error: error.message,
        host: (config.email.smtp && config.email.smtp.host) || 'unknown',
        port: (config.email.smtp && config.email.smtp.port) || 'unknown',
      });
    });
}

/**
 * Send an email
 * @param {string} to
 * @param {string} subject
 * @param {string} text
 * @returns {Promise}
 */
const sendEmail = async (to, subject, text) => {
  logger.info('Sending email', { to, subject, from: config.email.from });
  const msg = { from: config.email.from, to, subject, text };
  try {
    const info = await transport.sendMail(msg);
    logger.info('Email sent successfully', {
      to,
      subject,
      messageId: info.messageId,
    });
    return info;
  } catch (error) {
    logger.error('Failed to send email', {
      to,
      subject,
      error: error.message,
      stack: error.stack,
    });
    throw error;
  }
};

/**
 * Send reset password email
 * @param {string} to
 * @param {string} token
 * @returns {Promise}
 */
const sendResetPasswordEmail = async (to, token) => {
  const subject = 'Reset password';
  // replace this url with the link to the reset password page of your front-end app
  const resetPasswordUrl = `${config.frontend.url}/reset-password?token=${token}`;
  const text = `Dear user,
To reset your password, click on this link: ${resetPasswordUrl}
If you did not request any password resets, then ignore this email.`;
  await sendEmail(to, subject, text);
};

/**
 * Send verification email
 * @param {string} to
 * @param {string} token
 * @returns {Promise}
 */
const sendVerificationEmail = async (to, token) => {
  const subject = 'Email Verification';
  // replace this url with the link to the email verification page of your front-end app
  const verificationEmailUrl = `${config.frontend.url}/verify-email?token=${token}`;
  const text = `Dear user,
To verify your email, click on this link: ${verificationEmailUrl}
If you did not create an account, then ignore this email.`;
  await sendEmail(to, subject, text);
};

module.exports = {
  transport,
  sendEmail,
  sendResetPasswordEmail,
  sendVerificationEmail,
};
