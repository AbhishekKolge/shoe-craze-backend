const Joi = require('joi');

const createOrderSchema = (req, res, next) => {
  const schema = Joi.object().keys({
    addressId: Joi.string().required(),
    coupon: Joi.string().allow(null, '').optional(),
  });

  req.schema = schema;

  next();
};

const verifyOrderSchema = (req, res, next) => {
  const schema = Joi.object().keys({
    paymentId: Joi.string().required(),
    signature: Joi.string().required(),
    orderId: Joi.string().required(),
  });

  req.schema = schema;

  next();
};

module.exports = {
  createOrderSchema,
  verifyOrderSchema,
};
