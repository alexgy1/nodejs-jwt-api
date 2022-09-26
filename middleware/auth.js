const jwt = require('jsonwebtoken');
const { TOKEN_KEY } = process.env;

const verifyToken = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers['x-access-token'];
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }
  //has token
  try {
    //compare
    const decoded = jwt.verify(token, TOKEN_KEY);
    //add attribute to req object can be used later
    req.user = decoded;
  } catch (error) {
    return res.status(401).send('Invalid Token');
  }
  return next();
};

module.exports = verifyToken;
