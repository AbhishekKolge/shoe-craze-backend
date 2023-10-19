const express = require("express");

const {
  createAddress,
  getAllAddresses,
  updateAddress,
  deleteAddress,
} = require("../controllers/addressController");
const {
  authenticateUserMiddleware,
  authorizePermissionsMiddleware,
} = require("../middleware/authentication");
const {
  createAddressSchema,
  updateAddressSchema,
  deleteAddressSchema,
} = require("../validation/address");
const { validateRequest } = require("../middleware/validate-request");
const { testUserMiddleware } = require("../middleware/test-user");

const router = express.Router();

router
  .route("/")
  .get(
    [authenticateUserMiddleware, authorizePermissionsMiddleware("BASIC")],
    getAllAddresses
  )
  .post(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware("BASIC"),
      testUserMiddleware,
      createAddressSchema,
      validateRequest,
    ],
    createAddress
  );

router
  .route("/:id")
  .patch(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware("BASIC"),
      testUserMiddleware,
      updateAddressSchema,
      validateRequest,
    ],
    updateAddress
  )
  .delete(
    [
      authenticateUserMiddleware,
      authorizePermissionsMiddleware("BASIC"),
      testUserMiddleware,
      deleteAddressSchema,
      validateRequest,
    ],
    deleteAddress
  );

module.exports = router;
