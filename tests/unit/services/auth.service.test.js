const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { authService } = require('../../../src/services');
const { userService, tokenService } = require('../../../src/services');
const { User, Token } = require('../../../src/models');
const ApiError = require('../../../src/utils/ApiError');
const { tokenTypes } = require('../../../src/config/tokens');
const { userOne, insertUsers } = require('../../fixtures/user.fixture');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('Auth service', () => {
  describe('loginUserWithEmailAndPassword', () => {
    test('should return user if email and password match', async () => {
      await insertUsers([userOne]);

      const result = await authService.loginUserWithEmailAndPassword(userOne.email, userOne.password);

      expect(result).toBeDefined();
      expect(result.email).toBe(userOne.email);
      expect(result.name).toBe(userOne.name);
    });

    test('should throw unauthorized error if email does not exist', async () => {
      await expect(authService.loginUserWithEmailAndPassword('nonexistent@example.com', 'password1')).rejects.toThrow(
        ApiError
      );
      await expect(authService.loginUserWithEmailAndPassword('nonexistent@example.com', 'password1')).rejects.toThrow(
        'Incorrect email or password'
      );
    });

    test('should throw unauthorized error if password is incorrect', async () => {
      await insertUsers([userOne]);

      await expect(authService.loginUserWithEmailAndPassword(userOne.email, 'wrongpassword')).rejects.toThrow(ApiError);
      await expect(authService.loginUserWithEmailAndPassword(userOne.email, 'wrongpassword')).rejects.toThrow(
        'Incorrect email or password'
      );
    });

    test('should throw unauthorized error if user is null', async () => {
      // Mock userService to return null
      const originalGetUserByEmail = userService.getUserByEmail;
      userService.getUserByEmail = jest.fn().mockResolvedValue(null);

      await expect(authService.loginUserWithEmailAndPassword(userOne.email, userOne.password)).rejects.toThrow(ApiError);
      await expect(authService.loginUserWithEmailAndPassword(userOne.email, userOne.password)).rejects.toThrow(
        'Incorrect email or password'
      );

      // Restore original function
      userService.getUserByEmail = originalGetUserByEmail;
    });
  });

  describe('logout', () => {
    test('should remove refresh token from database', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
      const refreshToken = tokenService.generateToken(userOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne._id, expires, tokenTypes.REFRESH);

      await authService.logout(refreshToken);

      const dbRefreshToken = await Token.findOne({ token: refreshToken });
      expect(dbRefreshToken).toBeNull();
    });

    test('should throw not found error if refresh token does not exist', async () => {
      const fakeToken = 'fake-refresh-token';

      await expect(authService.logout(fakeToken)).rejects.toThrow(ApiError);
      await expect(authService.logout(fakeToken)).rejects.toThrow('Not found');
    });

    test('should throw not found error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const refreshToken = tokenService.generateToken(userOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne._id, expires, tokenTypes.REFRESH, true);

      await expect(authService.logout(refreshToken)).rejects.toThrow(ApiError);
      await expect(authService.logout(refreshToken)).rejects.toThrow('Not found');
    });
  });

  describe('refreshAuth', () => {
    test('should return new auth tokens if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const refreshToken = tokenService.generateToken(userOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne._id, expires, tokenTypes.REFRESH);

      const result = await authService.refreshAuth(refreshToken);

      expect(result).toHaveProperty('access');
      expect(result).toHaveProperty('refresh');
      expect(result.access).toHaveProperty('token');
      expect(result.access).toHaveProperty('expires');
      expect(result.refresh).toHaveProperty('token');
      expect(result.refresh).toHaveProperty('expires');

      // Verify old refresh token is removed
      const oldToken = await Token.findOne({ token: refreshToken });
      expect(oldToken).toBeNull();
    });

    test('should throw unauthorized error if refresh token is invalid', async () => {
      const invalidToken = 'invalid-refresh-token';

      await expect(authService.refreshAuth(invalidToken)).rejects.toThrow(ApiError);
      await expect(authService.refreshAuth(invalidToken)).rejects.toThrow('Please authenticate');
    });

    test('should throw unauthorized error if user is not found', async () => {
      const userId = mongoose.Types.ObjectId();
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const refreshToken = tokenService.generateToken(userId, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userId, expires, tokenTypes.REFRESH);

      await expect(authService.refreshAuth(refreshToken)).rejects.toThrow(ApiError);
      await expect(authService.refreshAuth(refreshToken)).rejects.toThrow('Please authenticate');
    });

    test('should throw unauthorized error if refresh token is expired', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() - 1000); // Expired
      const refreshToken = tokenService.generateToken(userOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne._id, expires, tokenTypes.REFRESH);

      await expect(authService.refreshAuth(refreshToken)).rejects.toThrow(ApiError);
      await expect(authService.refreshAuth(refreshToken)).rejects.toThrow('Please authenticate');
    });
  });

  describe('resetPassword', () => {
    test('should reset password successfully', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      const resetPasswordToken = tokenService.generateToken(userOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne._id, expires, tokenTypes.RESET_PASSWORD);

      const newPassword = 'newPassword123';
      await authService.resetPassword(resetPasswordToken, newPassword);

      // Verify password is updated
      const updatedUser = await User.findById(userOne._id);
      const isPasswordMatch = await bcrypt.compare(newPassword, updatedUser.password);
      expect(isPasswordMatch).toBe(true);

      // Verify reset password tokens are deleted
      const resetTokens = await Token.find({ user: userOne._id, type: tokenTypes.RESET_PASSWORD });
      expect(resetTokens).toHaveLength(0);
    });

    test('should throw unauthorized error if reset token is invalid', async () => {
      const invalidToken = 'invalid-reset-token';
      const newPassword = 'newPassword123';

      await expect(authService.resetPassword(invalidToken, newPassword)).rejects.toThrow(ApiError);
      await expect(authService.resetPassword(invalidToken, newPassword)).rejects.toThrow('Password reset failed');
    });

    test('should throw unauthorized error if user is not found', async () => {
      const userId = mongoose.Types.ObjectId();
      const expires = new Date(Date.now() + 10 * 60 * 1000);
      const resetPasswordToken = tokenService.generateToken(userId, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userId, expires, tokenTypes.RESET_PASSWORD);

      const newPassword = 'newPassword123';

      await expect(authService.resetPassword(resetPasswordToken, newPassword)).rejects.toThrow(ApiError);
      await expect(authService.resetPassword(resetPasswordToken, newPassword)).rejects.toThrow('Password reset failed');
    });

    test('should throw unauthorized error if reset token is expired', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() - 1000); // Expired
      const resetPasswordToken = tokenService.generateToken(userOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne._id, expires, tokenTypes.RESET_PASSWORD);

      const newPassword = 'newPassword123';

      await expect(authService.resetPassword(resetPasswordToken, newPassword)).rejects.toThrow(ApiError);
      await expect(authService.resetPassword(resetPasswordToken, newPassword)).rejects.toThrow('Password reset failed');
    });
  });

  describe('verifyEmail', () => {
    test('should verify email successfully', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      const verifyEmailToken = tokenService.generateToken(userOne._id, expires, tokenTypes.VERIFY_EMAIL);
      await tokenService.saveToken(verifyEmailToken, userOne._id, expires, tokenTypes.VERIFY_EMAIL);

      await authService.verifyEmail(verifyEmailToken);

      // Verify email is marked as verified
      const updatedUser = await User.findById(userOne._id);
      expect(updatedUser.isEmailVerified).toBe(true);

      // Verify verify email tokens are deleted
      const verifyTokens = await Token.find({ user: userOne._id, type: tokenTypes.VERIFY_EMAIL });
      expect(verifyTokens).toHaveLength(0);
    });

    test('should throw unauthorized error if verify token is invalid', async () => {
      const invalidToken = 'invalid-verify-token';

      await expect(authService.verifyEmail(invalidToken)).rejects.toThrow(ApiError);
      await expect(authService.verifyEmail(invalidToken)).rejects.toThrow('Email verification failed');
    });

    test('should throw unauthorized error if user is not found', async () => {
      const userId = mongoose.Types.ObjectId();
      const expires = new Date(Date.now() + 10 * 60 * 1000);
      const verifyEmailToken = tokenService.generateToken(userId, expires, tokenTypes.VERIFY_EMAIL);
      await tokenService.saveToken(verifyEmailToken, userId, expires, tokenTypes.VERIFY_EMAIL);

      await expect(authService.verifyEmail(verifyEmailToken)).rejects.toThrow(ApiError);
      await expect(authService.verifyEmail(verifyEmailToken)).rejects.toThrow('Email verification failed');
    });

    test('should throw unauthorized error if verify token is expired', async () => {
      await insertUsers([userOne]);
      const expires = new Date(Date.now() - 1000); // Expired
      const verifyEmailToken = tokenService.generateToken(userOne._id, expires, tokenTypes.VERIFY_EMAIL);
      await tokenService.saveToken(verifyEmailToken, userOne._id, expires, tokenTypes.VERIFY_EMAIL);

      await expect(authService.verifyEmail(verifyEmailToken)).rejects.toThrow(ApiError);
      await expect(authService.verifyEmail(verifyEmailToken)).rejects.toThrow('Email verification failed');
    });
  });
});
