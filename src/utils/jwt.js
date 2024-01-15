const jwt = require('jsonwebtoken');

const createJWT = ({
  payload,
  expiresIn = process.env.TOKEN_EXPIRATION_TIME,
}) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: `${expiresIn}ms`,
  });
  return token;
};

const isTokenValid = (token) => jwt.verify(token, process.env.JWT_SECRET);

const attachCookiesToResponse = ({ res, req, tokenUser }) => {
  const token = createJWT({ payload: tokenUser });

  res.cookie(req.header('Origin'), token, {
    httpOnly: true,
    maxAge: process.env.TOKEN_EXPIRATION_TIME,
    secure: true,
    signed: true,
    sameSite: 'none',
  });
};

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
};
