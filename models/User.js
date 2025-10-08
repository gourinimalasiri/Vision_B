import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import validator from 'validator';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const userSchema = new mongoose.Schema(
  {
    // Common fields for all users
    title: {
      type: String,
      enum: ['Mr', 'Mrs', 'Miss', 'Rev', 'Dr', 'Prof'],
      required: true,
    },
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },
    nic: {
      type: String,
      required: [true, 'NIC is required'],
      unique: true,
      trim: true,
    },
    mobileNumber: {
      type: String,
      required: [true, 'Mobile number is required'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },
    role: {
      type: String,
      enum: ['patient', 'clinical_staff', 'admin'],
      required: true,
    },

    // Role-specific fields
    userIdentifier: {
      type: String,
      unique: true,
      sparse: true, // Allows multiple null values
    },

    // Patient specific fields
    dateOfBirth: {
      type: Date,
      required: function () {
        return this.role === 'patient';
      },
    },
    affectedEye: {
      type: String,
      enum: ['right', 'left', 'both'],
      required: function () {
        return this.role === 'patient';
      },
    },
    consultantDoctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: function () {
        return this.role === 'patient';
      },
    },
    pastMedicalHistory: {
      type: String,
      required: function () {
        return this.role === 'patient';
      },
    },
    allergies: {
      type: String,
      default: 'None',
    },

    // Clinical staff specific fields
    staffType: {
      type: String,
      enum: ['consultant_ophthalmologist', 'staff_nurse', 'optometrist'],
      required: function () {
        return this.role === 'clinical_staff';
      },
    },
    registrationId: {
      type: String,
      required: function () {
        return this.role === 'clinical_staff';
      },
    },

    // Admin specific fields
    designation: {
      type: String,
      required: function () {
        return this.role === 'admin';
      },
    },

    // Authentication and system fields
    tokens: [
      {
        name: {
          type: String,
          required: true,
          enum: [
            'auth',
            'email_verification',
            'password_reset',
            'api',
            'other',
          ],
        },
        token: {
          type: String,
          required: true,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
        expiresAt: {
          type: Date,
          required: true,
        },
        metadata: {
          type: Map,
          of: mongoose.Schema.Types.Mixed,
          default: {},
        },
      },
    ],
    isVerified: {
      type: Boolean,
      default: false,
    },
    lastLogin: {
      type: Date,
    },
    passwordChangedAt: Date,
    active: {
      type: Boolean,
      default: true,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
);

// Virtual for full name
userSchema.virtual('fullName').get(function () {
  return `${this.title} ${this.firstName} ${this.lastName}`;
});

// Virtual for patient UPIN
userSchema.virtual('upin').get(function () {
  return this.role === 'patient' ? this.userIdentifier : undefined;
});

// Virtual for staff ID
userSchema.virtual('staffId').get(function () {
  return this.role === 'clinical_staff' || this.role === 'admin'
    ? this.userIdentifier
    : undefined;
});

// Pre-save hook to generate user identifier
userSchema.pre('save', async function (next) {
  if (this.isNew && !this.userIdentifier) {
    try {
      const { generateUserIdentifier } = await import(
        '../utils/userIdGenerator.js'
      );
      this.userIdentifier = await generateUserIdentifier(this.role);
      next();
    } catch (error) {
      next(error);
    }
  } else {
    next();
  }
});

// Pre-save hook to hash password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Pre-save hook to set passwordChangedAt
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Pre-save hook to cleanup expired tokens
userSchema.pre('save', function (next) {
  const now = new Date();
  this.tokens = this.tokens.filter((tokenObj) => tokenObj.expiresAt > now);
  next();
});

// Method to generate JWT token
userSchema.methods.generateAuthToken = function () {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is not defined');
  }

  const payload = {
    _id: this._id,
    userIdentifier: this.userIdentifier,
    role: this.role,
    email: this.email,
    isVerified: this.isVerified,
    ...(this.role === 'clinical_staff' && { staffType: this.staffType }),
  };

  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
};

// Method to generate email verification token
userSchema.methods.generateEmailVerificationToken = function () {
  if (!process.env.JWT_EMAIL_SECRET) {
    throw new Error('JWT_EMAIL_SECRET environment variable is not defined');
  }

  const payload = {
    userId: this._id,
    email: this.email,
    purpose: 'email_verification',
  };

  return jwt.sign(payload, process.env.JWT_EMAIL_SECRET, {
    expiresIn: '24h',
  });
};

// Method to save token with name and expiration
userSchema.methods.saveToken = async function (
  name,
  token,
  expiresIn = '7d',
  metadata = {},
) {
  const expiresInMs = this._convertExpiresToMs(expiresIn);
  const expiresAt = new Date(Date.now() + expiresInMs);

  const tokenObj = {
    name,
    token,
    expiresAt,
    metadata,
  };

  // Remove existing tokens with same name
  this.tokens = this.tokens.filter((t) => t.name !== name);

  // Add new token
  this.tokens.push(tokenObj);
  await this.save();

  return token;
};

// Method to get token by name
userSchema.methods.getToken = function (name) {
  const tokenObj = this.tokens.find(
    (t) => t.name === name && t.expiresAt > new Date(),
  );
  return tokenObj ? tokenObj.token : null;
};

// Method to get token object by name
userSchema.methods.getTokenObject = function (name) {
  return this.tokens.find((t) => t.name === name && t.expiresAt > new Date());
};

// Method to remove token by name
userSchema.methods.removeToken = async function (name) {
  this.tokens = this.tokens.filter((tokenObj) => tokenObj.name !== name);
  await this.save();
};

// Method to create password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.saveToken('password_reset', hashedToken, '10m', {
    purpose: 'password_reset',
    createdAt: new Date(),
  });

  return resetToken;
};

// Method to verify password reset token
userSchema.methods.verifyPasswordResetToken = function (token) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const tokenObj = this.getTokenObject('password_reset');
  if (!tokenObj) {
    return false;
  }
  return tokenObj.token === hashedToken;
};

// Save auth token
userSchema.methods.generateAndSaveAuthToken = async function () {
  const token = this.generateAuthToken();
  return await this.saveToken(
    'auth',
    token,
    process.env.JWT_EXPIRES_IN || '7d',
    {
      device: 'web',
      createdAt: new Date(),
    },
  );
};

// Save email verification token
userSchema.methods.generateAndSaveEmailVerificationToken = async function () {
  let token = this.generateEmailVerificationToken();
  token = token.trim();
  return await this.saveToken('email_verification', token, '24h', {
    purpose: 'verify_email',
    generatedAt: new Date(),
  });
};

// Method to verify email using token
userSchema.methods.verifyEmailWithToken = async function () {
  const tokenObj = this.getTokenObject('email_verification');
  if (!tokenObj) {
    throw new Error('No valid email verification token found');
  }

  try {
    const decoded = jwt.verify(tokenObj.token, process.env.JWT_EMAIL_SECRET);
    if (decoded.userId.toString() !== this._id.toString()) {
      throw new Error('Invalid token for this user');
    }

    this.isVerified = true;
    await this.removeToken('email_verification');
    await this.save();

    return true;
  } catch (error) {
    await this.removeToken('email_verification');
    throw error;
  }
};

// Helper method to convert expiresIn to milliseconds
userSchema.methods._convertExpiresToMs = function (expiresIn) {
  if (typeof expiresIn === 'number') {
    return expiresIn * 1000;
  }

  const units = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
    w: 7 * 24 * 60 * 60 * 1000,
  };

  const match = expiresIn.match(/^(\d+)([smhdw])$/);
  if (match) {
    const value = parseInt(match[1]);
    const unit = match[2];
    return value * units[unit];
  }

  return 7 * 24 * 60 * 60 * 1000;
};

// Method to compare passwords
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword,
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Method to check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10,
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Query middleware to filter out inactive users
userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

const User = mongoose.model('User', userSchema);

export default User;
