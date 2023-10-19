const removeQuotes = (str) => {
  return str.replace(/['"]+/g, '');
};

const getDiscountedPrice = ({ price, discountAmount, discount }) => {
  let finalPrice = price;
  if (discountAmount) {
    if (discount === 'FIXED') {
      finalPrice = parseFloat(parseFloat(price - discountAmount).toFixed(2));
    } else {
      finalPrice = parseFloat(
        parseFloat(price - (discountAmount / 100) * price).toFixed(2)
      );
    }
  }

  return finalPrice;
};

const getAppliedCouponPrice = ({ type, amount, price }) => {
  let finalPrice = price;
  let discountPrice = amount;

  if (type === 'FIXED') {
    finalPrice = parseFloat(parseFloat(price - amount).toFixed(2));
  } else {
    discountPrice = parseFloat(parseFloat((amount / 100) * price).toFixed(2));
    finalPrice = parseFloat(
      parseFloat(price - (amount / 100) * price).toFixed(2)
    );
  }

  return { finalPrice, discountPrice };
};

module.exports = { removeQuotes, getDiscountedPrice, getAppliedCouponPrice };
