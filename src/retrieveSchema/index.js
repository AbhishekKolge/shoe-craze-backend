const user = {
  id: true,
  firstName: true,
  lastName: true,
  contactNo: true,
  email: true,
  status: true,
  gender: true,
  dob: true,
  profileImage: true,
  profileImageId: true,
};

const users = {
  id: true,
  firstName: true,
  lastName: true,
  contactNo: true,
  email: true,
  role: true,
  status: true,
  isVerified: true,
  authorized: true,
};

const returnReason = {
  id: true,
  title: true,
};

const category = {
  id: true,
  name: true,
};

const size = {
  id: true,
  value: true,
};

const coupon = {
  id: true,
  type: true,
  amount: true,
  code: true,
  startTime: true,
  expiryTime: true,
  valid: true,
  maxRedemptions: true,
  totalRedemptions: true,
  createdAt: true,
  updatedAt: true,
};

const review = {
  id: true,
  rating: true,
  comment: true,
  createdAt: true,
  updatedAt: true,
  user: {
    select: {
      id: true,
      firstName: true,
      lastName: true,
      profileImage: true,
    },
  },
};

const products = {
  id: true,
  name: true,
  price: true,
  discount: true,
  discountAmount: true,
  image: true,
  categoryId: true,
  description: true,
  featured: true,
  color: true,
  inventory: true,
  averageRating: true,
  numOfReviews: true,
  createdAt: true,
  updatedAt: true,
  sizes: {
    select: size,
  },
  category: {
    select: category,
  },
  wishListedBy: {
    select: {
      id: true,
    },
  },
  cartBy: {
    select: {
      id: true,
    },
  },
};

const cartProduct = {
  id: true,
  name: true,
  price: true,
  discount: true,
  discountAmount: true,
  color: true,
  inventory: true,
};

const userCart = {
  cart: {
    select: cartProduct,
  },
};

const cartPrice = {
  cart: {
    select: {
      price: true,
      discount: true,
      discountAmount: true,
    },
  },
};

const userCartPrice = {
  id: true,
  firstName: true,
  lastName: true,
  contactNo: true,
  email: true,
  cart: {
    select: {
      id: true,
      price: true,
      discount: true,
      discountAmount: true,
    },
  },
};

const product = {
  id: true,
  name: true,
  price: true,
  discount: true,
  discountAmount: true,
  image: true,
  featured: true,
  color: true,
  description: true,
  inventory: true,
  averageRating: true,
  numOfReviews: true,
  createdAt: true,
  updatedAt: true,
  category: {
    select: category,
  },
  wishListedBy: {
    select: {
      id: true,
    },
  },
  cartBy: {
    select: {
      id: true,
    },
  },
  sizes: {
    select: size,
  },
  userReviews: {
    take: 5,
    orderBy: [
      {
        createdAt: 'desc',
      },
    ],
    select: review,
  },
};

const address = {
  id: true,
  address: true,
  city: true,
  pincode: true,
  state: true,
  country: true,
  type: true,
};

const order = {
  id: true,
  orderId: true,
  user: {
    select: {
      id: true,
      firstName: true,
      lastName: true,
    },
  },
  products: {
    select: {
      id: true,
      name: true,
    },
  },
  subTotal: true,
  total: true,
  discount: true,
  coupon: {
    select: {
      code: true,
    },
  },
  isPaid: true,
  isDelivered: true,
};

module.exports = {
  user,
  users,
  userCart,
  cartPrice,
  userCartPrice,
  returnReason,
  category,
  size,
  coupon,
  products,
  product,
  review,
  address,
  order,
};
