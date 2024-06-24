const moment = require('moment-timezone');
const pool = require('../config/db'); // Adjust the path to your db configuration file

const logAction = async (userId, action, details) => {
  const timestamp = moment().tz(process.env.TZ).format();
  await pool.query('INSERT INTO audit_log (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)', [userId, action, details, timestamp]);
};

const auditLogMiddleware = (action) => {
  return async (req, res, next) => {
    const { userId } = req.body;
    const details = JSON.stringify(req.body);
    await logAction(userId, action, details);
    next();
  };
};

module.exports = auditLogMiddleware;