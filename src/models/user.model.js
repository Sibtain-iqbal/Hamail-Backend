const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { toJSON, paginate } = require('./plugins');
const { roles } = require('../config/roles');
const { encrypt, decrypt } = require('../utils/encryption');

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate(value) {
        if (!validator.isEmail(value)) {
          throw new Error('Invalid email');
        }
      },
    },
    password: {
      type: String,
      required() {
        return !this.googleId; // Password is required only if not using Google OAuth
      },
      trim: true,
      minlength: 8,
      validate(value) {
        if (value && (!value.match(/\d/) || !value.match(/[a-zA-Z]/))) {
          throw new Error('Password must contain at least one letter and one number');
        }
      },
      private: true, // used by the toJSON plugin
    },
    googleId: {
      type: String,
      sparse: true, // allows multiple null values
      unique: true,
    },
    role: {
      type: String,
      enum: roles,
      default: 'user',
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    mt5Account: {
      accountId: {
        type: String,
        trim: true,
      },
      server: {
        type: String,
        trim: true,
      },
      password: {
        type: String,
        private: true, // Encrypted using AES-256-GCM
      },
      isConnected: {
        type: Boolean,
        default: false,
      },
      lastSyncAt: {
        type: Date,
      },
    },
  },
  {
    timestamps: true,
  }
);

// include virtuals in JSON output to allow populated virtual fields to appear
userSchema.set('toJSON', { virtuals: true });

// virtual relations
userSchema.virtual('tradingPlans', {
  ref: 'TradingPlan',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
});

userSchema.virtual('trades', {
  ref: 'Trade',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
});

userSchema.virtual('stateAnalyses', {
  ref: 'StateAnalysis',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
});

userSchema.virtual('sessionForecasts', {
  ref: 'SessionForecast',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
});

userSchema.virtual('performanceSnapshots', {
  ref: 'PerformanceSnapshot',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
});

userSchema.virtual('dashboard', {
  ref: 'Dashboard',
  localField: '_id',
  foreignField: 'userId',
  justOne: true,
});

// add plugin that converts mongoose to json
userSchema.plugin(toJSON);
userSchema.plugin(paginate);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isEmailTaken = async function (email, excludeUserId) {
  const user = await this.findOne({ email, _id: { $ne: excludeUserId } });
  return !!user;
};

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<boolean>}
 */
userSchema.methods.isPasswordMatch = async function (password) {
  const user = this;
  return bcrypt.compare(password, user.password);
};

/**
 * Get decrypted MT5 password
 * @returns {string} Decrypted MT5 password
 */
userSchema.methods.getMT5Password = function () {
  if (!this.mt5Account || !this.mt5Account.password) {
    return null;
  }
  return decrypt(this.mt5Account.password);
};

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  if (user.isModified('mt5Account.password') && user.mt5Account.password) {
    user.mt5Account.password = encrypt(user.mt5Account.password);
  }
  next();
});

/**
 * @typedef User
 */
const User = mongoose.model('User', userSchema);

module.exports = User;
