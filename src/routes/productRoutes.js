const express = require('express');

const {
  createProduct,
  getAllProducts,
  updateProduct,
  getSingleProduct,
  deleteProduct,
  addProductToWishList,
  removeProductFromWishList,
  addProductToCart,
  removeProductFromCart,
} = require('../controllers/productController');
const {
  authenticateUserMiddleware,
  authorizePermissionsMiddleware,
  attachUserIfExists,
} = require('../middleware/authentication');
const {
  createProductSchema,
  updateProductSchema,
  deleteProductSchema,
  addProductToWishListSchema,
  removeProductFromWishListSchema,
  addProductToCartSchema,
  removeProductFromCartSchema,
} = require('../validation/product');
const { validateRequest } = require('../middleware/validate-request');
const { testUserMiddleware } = require('../middleware/test-user');

const router = express.Router();

router
  .route('/')
  .get(attachUserIfExists, getAllProducts)
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('ADMIN'),
      testUserMiddleware,
      createProductSchema,
      validateRequest,
    ],
    createProduct
  );

router
  .route('/wishlist/:id')
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      testUserMiddleware,
      addProductToWishListSchema,
      validateRequest,
    ],
    addProductToWishList
  )
  .delete(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      testUserMiddleware,
      removeProductFromWishListSchema,
      validateRequest,
    ],
    removeProductFromWishList
  );

router
  .route('/cart/:id')
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      testUserMiddleware,
      addProductToCartSchema,
      validateRequest,
    ],
    addProductToCart
  )
  .delete(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('BASIC'),
      testUserMiddleware,
      removeProductFromCartSchema,
      validateRequest,
    ],
    removeProductFromCart
  );

router
  .route('/:id')
  .get(attachUserIfExists, getSingleProduct)
  .patch(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('ADMIN'),
      testUserMiddleware,
      updateProductSchema,
      validateRequest,
    ],
    updateProduct
  )
  .delete(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware('ADMIN'),
      testUserMiddleware,
      deleteProductSchema,
      validateRequest,
    ],
    deleteProduct
  );

module.exports = router;
