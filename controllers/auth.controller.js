import mongoose from 'mongoose';
import validator from 'validator';
import User from '../models/User.js';
import { sendWelcomeEmail } from '../utils/emailService.js';

export const registerUser = async (req, res) => {
  // Validate critical dependencies first
  if (!mongoose.connection.readyState) {
    return res.status(500).json({
      success: false,
      message: 'Database connection not available',
    });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const {
      title,
      firstName,
      lastName,
      email,
      password,
      nic,
      mobileNumber,
      role = 'patient',
      // Patient specific fields
      dateOfBirth,
      affectedEye,
      consultantDoctor,
      pastMedicalHistory,
      allergies,
      // Clinical staff specific fields
      staffType,
      registrationId,
      // Admin specific fields
      designation,
    } = req.body;

    // Input validation for common required fields
    if (
      !title ||
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !nic ||
      !mobileNumber
    ) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided',
        requiredFields: [
          'title',
          'firstName',
          'lastName',
          'email',
          'password',
          'nic',
          'mobileNumber',
        ],
      });
    }

    // Role-specific validation
    if (role === 'patient') {
      if (!dateOfBirth || !affectedEye || !pastMedicalHistory) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message:
            'Patient registration requires dateOfBirth, affectedEye, and pastMedicalHistory',
        });
      }
    } else if (role === 'clinical_staff') {
      if (!staffType || !registrationId) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message:
            'Clinical staff registration requires staffType and registrationId',
        });
      }
    } else if (role === 'admin') {
      if (!designation) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Admin registration requires designation',
        });
      }
    }

    // Sanitize inputs
    const sanitizedData = {
      title: title.toString().trim(),
      firstName: firstName.toString().trim(),
      lastName: lastName.toString().trim(),
      email: email.toString().toLowerCase().trim(),
      password: password.toString(),
      nic: nic.toString().trim(),
      mobileNumber: mobileNumber.toString().trim(),
      role: role.toString(),
      // Patient fields
      ...(dateOfBirth && { dateOfBirth: new Date(dateOfBirth) }),
      ...(affectedEye && { affectedEye: affectedEye.toString().trim() }),
      ...(consultantDoctor && {
        consultantDoctor: consultantDoctor.toString().trim(),
      }),
      ...(pastMedicalHistory && {
        pastMedicalHistory: pastMedicalHistory.toString().trim(),
      }),
      allergies: allergies ? allergies.toString().trim() : 'None',
      // Clinical staff fields
      ...(staffType && { staffType: staffType.toString().trim() }),
      ...(registrationId && {
        registrationId: registrationId.toString().trim(),
      }),
      // Admin fields
      ...(designation && { designation: designation.toString().trim() }),
    };

    // Email validation
    if (!validator.isEmail(sanitizedData.email)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address',
      });
    }

    // Password strength validation
    if (password.length < 8) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long',
      });
    }

    // NIC validation (basic)
    if (sanitizedData.nic.length < 5) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid NIC',
      });
    }

    // Mobile number validation (basic)
    if (sanitizedData.mobileNumber.length < 9) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid mobile number',
      });
    }

    // Check for existing user by email or NIC
    const User = mongoose.model('User');
    const existingUser = await User.findOne({
      $or: [{ email: sanitizedData.email }, { nic: sanitizedData.nic }],
    }).session(session);

    if (existingUser) {
      await session.abortTransaction();
      const field =
        existingUser.email === sanitizedData.email ? 'email' : 'NIC';
      return res.status(409).json({
        success: false,
        message: `${
          field.charAt(0).toUpperCase() + field.slice(1)
        } is already registered`,
      });
    }

    // Create user
    const newUser = await User.create(
      [
        {
          title: sanitizedData.title,
          firstName: sanitizedData.firstName,
          lastName: sanitizedData.lastName,
          email: sanitizedData.email,
          password: sanitizedData.password,
          nic: sanitizedData.nic,
          mobileNumber: sanitizedData.mobileNumber,
          role: sanitizedData.role,
          // Patient specific fields
          ...(role === 'patient' && {
            dateOfBirth: sanitizedData.dateOfBirth,
            affectedEye: sanitizedData.affectedEye,
            consultantDoctor: sanitizedData.consultantDoctor,
            pastMedicalHistory: sanitizedData.pastMedicalHistory,
            allergies: sanitizedData.allergies,
          }),
          // Clinical staff specific fields
          ...(role === 'clinical_staff' && {
            staffType: sanitizedData.staffType,
            registrationId: sanitizedData.registrationId,
          }),
          // Admin specific fields
          ...(role === 'admin' && {
            designation: sanitizedData.designation,
          }),
          // All users start as verified for simplicity (adjust as needed)
          isVerified: true,
          active: true,
        },
      ],
      { session },
    );

    const user = newUser[0];

    // Generate and save auth token using named token system
    const authToken = await user.generateAndSaveAuthToken();

    // Generate email verification token (if you want email verification)
    let emailVerificationToken = null;
    // Uncomment if you want email verification
    // emailVerificationToken = await user.generateAndSaveEmailVerificationToken();
    // await user.save({ session });

    // Prepare response data
    const userData = {
      _id: user._id,
      userIdentifier: user.userIdentifier,
      title: user.title,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      nic: user.nic,
      mobileNumber: user.mobileNumber,
      role: user.role,
      isVerified: user.isVerified,
      createdAt: user.createdAt,
      // Role-specific identifiers
      ...(user.role === 'patient' && { upin: user.userIdentifier }),
      ...((user.role === 'clinical_staff' || user.role === 'admin') && {
        staffId: user.userIdentifier,
      }),
      // Role-specific data
      ...(user.role === 'patient' && {
        dateOfBirth: user.dateOfBirth,
        affectedEye: user.affectedEye,
        consultantDoctor: user.consultantDoctor,
        pastMedicalHistory: user.pastMedicalHistory,
        allergies: user.allergies,
      }),
      ...(user.role === 'clinical_staff' && {
        staffType: user.staffType,
        registrationId: user.registrationId,
      }),
      ...(user.role === 'admin' && {
        designation: user.designation,
      }),
    };

    // Send welcome email
    try {
      await sendWelcomeEmail(
        user,
        emailVerificationToken || 'welcome_token_placeholder',
      );
    } catch (emailError) {
      console.error('Email sending failed:', emailError.message);
      // Don't fail registration if email fails
    }

    // Commit transaction
    await session.commitTransaction();

    // Set HTTP-only cookie
    res.cookie('token', authToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'strict',
      path: '/',
    });

    // Prepare success response based on role
    let successMessage = '';
    switch (role) {
      case 'patient':
        successMessage =
          'Patient registration completed successfully! Your UPIN has been generated.';
        break;
      case 'clinical_staff':
        successMessage =
          'Clinical staff registration completed successfully! Your Staff ID has been generated.';
        break;
      case 'admin':
        successMessage =
          'Admin registration completed successfully! Your Admin ID has been generated.';
        break;
      default:
        successMessage = 'Registration completed successfully!';
    }

    return res.status(201).json({
      success: true,
      message: successMessage,
      data: userData,
      requiresVerification: !!emailVerificationToken, // Will be false since we're not using verification yet
      token: authToken, // Still return token for mobile apps, but cookie for web
    });
  } catch (error) {
    await session.abortTransaction();

    console.error('Registration process error:', error);

    // User-friendly error messages
    let statusCode = 500;
    let message = 'Registration failed due to system error';

    if (error.name === 'ValidationError') {
      statusCode = 400;
      message = 'Invalid input data provided';

      // Extract validation errors
      const validationErrors = {};
      if (error.errors) {
        Object.keys(error.errors).forEach((field) => {
          validationErrors[field] = error.errors[field].message;
        });
      }

      return res.status(statusCode).json({
        success: false,
        message: message,
        errors: validationErrors,
      });
    } else if (error.code === 11000) {
      statusCode = 409;
      if (error.keyPattern?.email) {
        message = 'Email address already exists';
      } else if (error.keyPattern?.nic) {
        message = 'NIC already registered';
      } else if (error.keyPattern?.userIdentifier) {
        message = 'User identifier generation conflict - please try again';
      } else {
        message = 'Duplicate entry found';
      }
    } else if (error.name === 'CastError') {
      statusCode = 400;
      message = 'Invalid data format';
    } else if (
      error.message.includes('JWT_SECRET') ||
      error.message.includes('JWT_EMAIL_SECRET')
    ) {
      statusCode = 500;
      message = 'Server configuration error - please contact support';
    }

    return res.status(statusCode).json({
      success: false,
      message: message,
      ...(process.env.NODE_ENV === 'development' && {
        error: error.message,
      }),
    });
  } finally {
    session.endSession();
  }
};
