const { createJWT, isTokenValid, attachCookiesToResponse } = require('./jwt');
const { createTokenUser } = require('./createTokenUser');
const { checkPermissions } = require('./checkPermissions');
const { nodeMailerConfig } = require('./emailConfig');
const { sendEmail } = require('./sendEmail');
const { sendVerificationEmail } = require('./sendVerificationEmail');
const { sendResetPasswordEmail } = require('./sendResetPasswordEmail');
const { hashString, createRandomBytes } = require('./createHash');
const {
  removeQuotes,
  getDiscountedPrice,
  getAppliedCouponPrice,
} = require('./format');
const { currentTime, checkTimeExpired, time } = require('./time');
const {
  getOrigin,
  getUserAgent,
  getRequestIp,
  checkTestUser,
} = require('./requestInfo');
const { createOrder, checkSign } = require('./razorpay');

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
  createTokenUser,
  checkPermissions,
  nodeMailerConfig,
  sendEmail,
  sendVerificationEmail,
  sendResetPasswordEmail,
  hashString,
  createRandomBytes,
  getOrigin,
  getUserAgent,
  getRequestIp,
  checkTestUser,
  removeQuotes,
  getDiscountedPrice,
  getAppliedCouponPrice,
  currentTime,
  checkTimeExpired,
  time,
  createOrder,
  checkSign,
};
