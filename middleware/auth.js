const jwt = require('jsonwebtoken');
const SECRET_KEY = 'asaf1984arviv'; // Replace with your own secret key

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send({ success: false, message: 'No token provided.' });
  }

  jwt.verify(token.split(' ')[1], SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send({ success: false, message: 'Failed to authenticate token.' });
    }
    req.userId = decoded.userId;
    req.roleId = decoded.roleId;
    req.roleName = decoded.roleName;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.roleName !== 'admin') {
    return res.status(403).send({ success: false, message: 'Require Admin Role!' });
  }
  next();
};

const isManager = (req, res, next) => {
  if (req.roleName !== 'manager' && req.roleName !== 'admin') {
    return res.status(403).send({ success: false, message: 'Require Manager Role!' });
  }
  next();
};

module.exports = {
  verifyToken,
  isAdmin,
  isManager
};
