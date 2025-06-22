require('dotenv').config(); 
const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET || 'default-secret'; 

function verifyAccessToken(token) {
  //console.log("Secret used for auth header check: " + secret)
  return jwt.verify(token, secret); // will throw if invalid or expired
}

module.exports = { verifyAccessToken };