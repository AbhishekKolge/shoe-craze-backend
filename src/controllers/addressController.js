const { StatusCodes } = require('http-status-codes');

const prisma = require('../../prisma/prisma-client');

const CustomError = require('../errors');
const customUtils = require('../utils');
const retrieveSchema = require('../retrieveSchema');

const createAddress = async (req, res) => {
  const {
    body,
    user: { userId },
  } = req;

  const addressCount = await prisma.address.count({
    where: {
      userId,
    },
  });

  if (addressCount >= 3) {
    throw new CustomError.BadRequestError('Maximum 3 addresses can be added');
  }

  body.userId = userId;

  await prisma.address.create({
    data: body,
  });

  res.status(StatusCodes.CREATED).json({});
};

const getAllAddresses = async (req, res) => {
  const { userId } = req.user;

  const addresses = await prisma.address.findMany({
    where: {
      userId,
    },
    select: retrieveSchema.address,
  });

  res.status(StatusCodes.OK).json({ addresses });
};

const updateAddress = async (req, res) => {
  const {
    params: { id: addressId },
    body,
    user,
  } = req;

  const address = await prisma.address.findUnique({
    where: {
      id: addressId,
    },
  });

  if (!address) {
    throw new CustomError.NotFoundError(
      `No address found with id of ${addressId}`
    );
  }

  customUtils.checkPermissions(user, address.userId);

  await prisma.address.update({
    data: body,
    where: {
      id: addressId,
    },
  });

  res.status(StatusCodes.OK).json({});
};

const deleteAddress = async (req, res) => {
  const {
    params: { id: addressId },
    user,
  } = req;

  const address = await prisma.address.findUnique({
    where: {
      id: addressId,
    },
  });

  if (!address) {
    throw new CustomError.NotFoundError(
      `No address found with id of ${addressId}`
    );
  }

  customUtils.checkPermissions(user, address.userId);

  await prisma.address.delete({
    where: {
      id: addressId,
    },
  });

  res.status(StatusCodes.OK).json({});
};

module.exports = {
  createAddress,
  getAllAddresses,
  updateAddress,
  deleteAddress,
};
