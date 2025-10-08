import express from 'express';

import {
  verifyEmail,
  resendVerificationEmail,
  checkVerificationStatus,
} from '../controllers/user.controller.js';

const router = express.Router();

router.get('/verify-email', verifyEmail);

router.post('/resend-verification', resendVerificationEmail);

router.get('/verify-status/:userId', checkVerificationStatus);

export default router;
