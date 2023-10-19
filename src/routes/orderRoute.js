const express = require('express');

const {
  getCart,
  getCartPrice,
  createOrder,
  verifyOrder,
  getMyOrders,
  getOrders,
} = require('../controllers/orderController');
const {
  authenticateUserMiddleware,
  authorizePermissionsMiddleware,
} = require('../middleware/authentication');
const { createOrderSchema, verifyOrderSchema } = require('../validation/order');
const { validateRequest } = require('../middleware/validate-request');
const { testUserMiddleware } = require('../middleware/test-user');

const router = express.Router();

router
  .route('/')
  .get(
    [authenticateUserMiddleware, authorizePermissionsMiddleware('BASIC')],
    getMyOrders
  )
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      createOrderSchema,
      validateRequest,
    ],
    createOrder
  );
router
  .route('/all')
  .get(
    [authenticateUserMiddleware, authorizePermissionsMiddleware('ADMIN')],
    getOrders
  );
router
  .route('/verify')
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      verifyOrderSchema,
      validateRequest,
    ],
    verifyOrder
  );
router
  .route('/cart')
  .get(
    [authenticateUserMiddleware, authorizePermissionsMiddleware('BASIC')],
    getCart
  );

router
  .route('/cart/price')
  .get(
    [authenticateUserMiddleware, authorizePermissionsMiddleware('BASIC')],
    getCartPrice
  );

module.exports = router;
