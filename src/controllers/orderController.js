const { StatusCodes } = require('http-status-codes');

const prisma = require('../../prisma/prisma-client');

const CustomError = require('../errors');
const customUtils = require('../utils');
const retrieveSchema = require('../retrieveSchema');

const getCart = async (req, res) => {
  const { userId } = req.user;

  const { cart } = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: retrieveSchema.userCart,
  });

  res.status(StatusCodes.OK).json({ cart });
};

const getCartPrice = async (req, res) => {
  const { userId } = req.user;
  const { coupon } = req.query;

  let appliedCoupon = null;

  if (coupon) {
    appliedCoupon = await prisma.coupon.findUnique({
      where: {
        id: coupon,
        valid: true,
        expiryTime: {
          gte: new Date(),
        },
        totalRedemptions: { lt: prisma.coupon.fields.maxRedemptions },
      },
    });
  }

  const { cart } = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: retrieveSchema.cartPrice,
  });

  let total = 0;
  let discount = 0;
  let subTotal = 0;

  if (cart?.length) {
    total = cart.reduce((total, item) => {
      return total + customUtils.getDiscountedPrice(item);
    }, 0);
    subTotal = total;
  }

  if (appliedCoupon && total) {
    const { finalPrice, discountPrice } = customUtils.getAppliedCouponPrice({
      type: appliedCoupon.type,
      amount: appliedCoupon.amount,
      price: total,
    });
    total = finalPrice;
    discount = discountPrice;
  }

  res.status(StatusCodes.OK).json({ subTotal, total, discount, coupon });
};

const createOrder = async (req, res) => {
  const {
    body: { addressId, coupon },
    user: { userId },
  } = req;

  let appliedCoupon = null;

  if (coupon) {
    appliedCoupon = await prisma.coupon.findUnique({
      where: {
        id: coupon,
        valid: true,
        expiryTime: {
          gte: new Date(),
        },
        totalRedemptions: { lt: prisma.coupon.fields.maxRedemptions },
      },
    });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: retrieveSchema.userCartPrice,
  });

  let total = 0;
  let discount = 0;
  let subTotal = 0;

  if (user.cart?.length) {
    total = user.cart.reduce((total, item) => {
      return total + customUtils.getDiscountedPrice(item);
    }, 0);
    subTotal = total;
  }

  if (appliedCoupon && total) {
    const { finalPrice, discountPrice } = customUtils.getAppliedCouponPrice({
      type: appliedCoupon.type,
      amount: appliedCoupon.amount,
      price: total,
    });
    total = finalPrice;
    discount = discountPrice;
  }

  const order = await customUtils.createOrder(total);

  await prisma.order.create({
    data: {
      orderId: order.id,
      userId,
      addressId,
      subTotal,
      total,
      discount,
      couponId: coupon || null,
      products: {
        connect: user.cart.map((product) => ({ id: product.id })),
      },
    },
  });

  res
    .status(StatusCodes.OK)
    .json({ order, key: process.env.RAZORPAY_ID_KEY, user });
};

const verifyOrder = async (req, res) => {
  const { paymentId, signature, orderId } = req.body;

  const status = customUtils.checkSign({ paymentId, signature, orderId });

  const { products, couponId } = await prisma.order.update({
    data: {
      isPaid: true,
      paidAt: customUtils.currentTime(),
    },
    select: {
      products: {
        select: {
          id: true,
        },
      },
      couponId: true,
    },
    where: {
      orderId,
    },
  });

  await prisma.user.update({
    data: {
      cart: {
        disconnect: products,
      },
    },
    where: {
      id: req.user.userId,
    },
  });

  if (couponId) {
    await prisma.coupon.update({
      data: {
        totalRedemptions: { increment: 1 },
      },
      where: {
        id: couponId,
      },
    });
  }

  await prisma.product.updateMany({
    data: {
      inventory: { decrement: 1 },
    },
    where: {
      id: {
        in: products.map((product) => product.id),
      },
    },
  });

  res.status(StatusCodes.OK).json({});
};

const getMyOrders = async (req, res) => {
  const { userId } = req.user;

  const page = +req.query.page || 1;
  const take = 8;
  const skip = (page - 1) * take;

  const orders = await prisma.order.findMany({
    skip,
    take,
    where: {
      userId,
    },
    select: retrieveSchema.order,
    orderBy: [
      {
        createdAt: 'desc',
      },
    ],
  });

  const totalOrders = await prisma.order.count({
    where: {
      userId,
    },
  });
  const numOfPages = Math.ceil(totalOrders / take);

  res.status(StatusCodes.OK).json({ orders, totalOrders, numOfPages });
};

const getOrders = async (req, res) => {
  const { sort, priceSort, status } = req.query;

  let queryObject = {
    where: {},
    orderBy: [],
  };

  if (status && +status === 1) {
    queryObject.where = {
      ...queryObject.where,
      isPaid: true,
    };
  }

  if (status && +status === 0) {
    queryObject.where = {
      ...queryObject.where,
      isPaid: false,
    };
  }

  if (priceSort === 'highest') {
    queryObject.orderBy.push({
      total: 'desc',
    });
  }

  if (priceSort === 'lowest') {
    queryObject.orderBy.push({
      total: 'asc',
    });
  }

  if (sort == 'latest') {
    queryObject.orderBy.push({
      createdAt: 'desc',
    });
  }

  if (sort == 'oldest') {
    queryObject.orderBy.push({
      createdAt: 'asc',
    });
  }

  if (!sort) {
    queryObject.orderBy.push({
      createdAt: 'desc',
    });
  }

  const page = +req.query.page || 1;
  const take = 8;
  const skip = (page - 1) * take;

  let orders = await prisma.order.findMany({
    skip,
    take,
    ...queryObject,
    select: retrieveSchema.order,
  });

  const totalOrders = await prisma.order.count({
    ...queryObject,
  });
  const numOfPages = Math.ceil(totalOrders / take);

  res.status(StatusCodes.OK).json({ orders, totalOrders, numOfPages });
};

module.exports = {
  getCart,
  getCartPrice,
  createOrder,
  verifyOrder,
  getMyOrders,
  getOrders,
};
