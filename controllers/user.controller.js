import mongoose from 'mongoose';
import validator from 'validator';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import {
  sendWelcomeEmail,
  testEmailConnection,
  sendEmailVerificationSuccessEmail,
} from '../utils/emailService.js';

export const verifyEmail = async (req, res) => {
  try {
    let { token } = req.query;
    token = token.toString().trim();
    token = decodeURIComponent(token);
    console.log('🔍 Received token:', token);
    console.log('🔍 Token length:', token?.length);
    console.log('🔍 Token type:', typeof token);

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required',
      });
    }

    const User = mongoose.model('User');

    // First, let's find ALL users with email_verification tokens to debug
    const allUsersWithVerificationTokens = await User.find({
      'tokens.name': 'email_verification',
    });

    console.log(
      '🔍 Users with verification tokens:',
      allUsersWithVerificationTokens.length,
    );

    allUsersWithVerificationTokens.forEach((user) => {
      user.tokens.forEach((t) => {
        if (t.name === 'email_verification') {
          console.log('🔍 Stored token:', t.token);
          console.log('🔍 Stored token length:', t.token.length);
          console.log('🔍 Token matches?', t.token === token);
          console.log('🔍 Expires at:', t.expiresAt);
          console.log('🔍 Is expired?', t.expiresAt < new Date());
        }
      });
    });

    // Then try the actual query
    let user = await User.findOne({
      'tokens.name': 'email_verification',
      'tokens.token': token,
      'tokens.expiresAt': { $gt: new Date() },
    });

    console.log('🔍 Found user:', user ? 'Yes' : 'No');

    if (!user) {
      console.log('🔍 Exact match failed, trying JWT verification...');

      // Find all users with valid email verification tokens
      const potentialUsers = await User.find({
        'tokens.name': 'email_verification',
        'tokens.expiresAt': { $gt: new Date() },
      });

      for (const potentialUser of potentialUsers) {
        const tokenObj = potentialUser.getTokenObject('email_verification');
        if (tokenObj) {
          try {
            // Try to verify the stored token JWT
            const decodedStored = jwt.verify(
              tokenObj.token,
              process.env.JWT_EMAIL_SECRET || process.env.JWT_SECRET,
            );
            // Try to verify the received token JWT
            const decodedReceived = jwt.verify(
              token,
              process.env.JWT_EMAIL_SECRET || process.env.JWT_SECRET,
            );

            // If both tokens have the same payload, they're the same token
            if (
              decodedStored.userId.toString() ===
              decodedReceived.userId.toString()
            ) {
              user = potentialUser;
              console.log('🔍 Found user via JWT payload match');
              break;
            }
          } catch (jwtError) {
            // Continue to next user
            continue;
          }
        }
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token',
      });
    }

    // Verify the token
    try {
      jwt.verify(token, process.env.JWT_EMAIL_SECRET || process.env.JWT_SECRET);
    } catch (jwtError) {
      // Remove invalid token
      await user.removeToken('email_verification');

      if (jwtError.name === 'TokenExpiredError') {
        return res.status(400).json({
          success: false,
          message: 'Verification token has expired',
        });
      }

      return res.status(400).json({
        success: false,
        message: 'Invalid verification token',
      });
    }

    // Mark user as verified and remove verification token
    user.isVerified = true;
    await user.removeToken('email_verification');
    await user.save();

    console.log('✅ Email verified successfully for:', user.email);

    // Send verification success email
    try {
      await sendEmailVerificationSuccessEmail(user);
    } catch (emailError) {
      console.error(
        'Failed to send verification success email:',
        emailError.message,
      );
      // Continue even if email fails
    }

    return res.status(200).json({
      success: true,
      message:
        'Email verified successfully! You can now log in to your account.',
      data: {
        userIdentifier: user.userIdentifier,
        email: user.email,
        role: user.role,
        title: user.title,
        firstName: user.firstName,
        lastName: user.lastName,
        // Include role-specific identifiers
        ...(user.role === 'patient' && { upin: user.userIdentifier }),
        ...((user.role === 'clinical_staff' || user.role === 'admin') && {
          staffId: user.userIdentifier,
        }),
        ...(user.role === 'clinical_staff' && { staffType: user.staffType }),
        ...(user.role === 'admin' && { designation: user.designation }),
      },
    });
  } catch (error) {
    console.error('Email verification error:', error);

    return res.status(500).json({
      success: false,
      message: 'Email verification failed',
      ...(process.env.NODE_ENV === 'development' && {
        error: error.message,
      }),
    });
  }
};

/**
 * Resend email verification
 */
export const resendVerificationEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required',
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified',
      });
    }

    // Remove any existing email verification tokens
    await user.removeToken('email_verification');

    // Generate new verification token
    const verificationToken =
      await user.generateAndSaveEmailVerificationToken();

    // Send welcome email with new verification link
    await sendWelcomeEmail(user, verificationToken);

    return res.status(200).json({
      success: true,
      message: 'Verification email sent successfully',
    });
  } catch (error) {
    console.error('Resend verification email error:', error);

    return res.status(500).json({
      success: false,
      message: 'Failed to resend verification email',
      ...(process.env.NODE_ENV === 'development' && {
        error: error.message,
      }),
    });
  }
};

/**
 * Check email verification status
 */
export const checkVerificationStatus = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findOne({
      $or: [{ _id: userId }, { userIdentifier: userId }],
    }).select('email isVerified userIdentifier role title firstName lastName');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        email: user.email,
        isVerified: user.isVerified,
        userIdentifier: user.userIdentifier,
        role: user.role,
        title: user.title,
        firstName: user.firstName,
        lastName: user.lastName,
        ...(user.role === 'patient' && { upin: user.userIdentifier }),
        ...((user.role === 'clinical_staff' || user.role === 'admin') && {
          staffId: user.userIdentifier,
        }),
      },
    });
  } catch (error) {
    console.error('Check verification status error:', error);

    return res.status(500).json({
      success: false,
      message: 'Failed to check verification status',
      ...(process.env.NODE_ENV === 'development' && {
        error: error.message,
      }),
    });
  }
};
