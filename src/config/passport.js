const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const config = require('./config');
const { tokenTypes } = require('./tokens');
const { User } = require('../models');
const logger = require('./logger');

const jwtOptions = {
  secretOrKey: config.jwt.secret,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};

const jwtVerify = async (payload, done) => {
  try {
    if (payload.type !== tokenTypes.ACCESS) {
      throw new Error('Invalid token type');
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    done(error, false);
  }
};

const jwtStrategy = new JwtStrategy(jwtOptions, jwtVerify);

const googleStrategy = new GoogleStrategy(
  {
    clientID: config.google.clientId,
    clientSecret: config.google.clientSecret,
    callbackURL: '/v1/auth/google/callback',
    proxy: true,
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      logger.info('Google OAuth profile received googleId: %s email: %s', profile.id, profile.emails[0].value);

      // Check if user already exists with this Google ID
      let user = await User.findOne({ googleId: profile.id });

      if (user) {
        logger.info('Existing Google user found userId: %s email: %s', user.id, user.email);
        return done(null, user);
      }

      // Check if user exists with this email but no Google ID
      user = await User.findOne({ email: profile.emails[0].value });

      if (user) {
        // Link Google account to existing user
        user.googleId = profile.id;
        await user.save();
        logger.info('Linked Google account to existing user userId: %s email: %s', user.id, user.email);
        return done(null, user);
      }

      // Create new user
      user = await User.create({
        name: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id,
        isEmailVerified: true, // Google emails are pre-verified
      });

      logger.info('Created new Google user userId: %s email: %s', user.id, user.email);
      return done(null, user);
    } catch (error) {
      logger.error('Google OAuth error error: %s stack: %s', error.message, error.stack);
      return done(error, null);
    }
  }
);

module.exports = {
  jwtStrategy,
  googleStrategy,
};
