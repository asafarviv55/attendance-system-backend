const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./config/db'); // Import the database connection
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { verifyToken,isAdmin, isManager } = require('./middleware/auth');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Use crypto module for random bytes
const moment = require('moment-timezone');
const auditLogMiddleware = require('./middleware/auditLogMiddleware'); // Adjust the path to your audit log middleware


const app = express();
const port = 5000;

app.use(bodyParser.json());
app.use(cors()); // Enable CORS for all routes
const SECRET_KEY = process.env.SECRET_KEY ;


// Set up nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // You can use other services
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


const AUTHORIZED_LOCATIONS = [
  { latitude: 37.7749, longitude: -122.4194 }, // Example: San Francisco
  { latitude: 31.771959 , longitude: 35.217018 } ,// Example: San Francisco
/*  { latitude: 31.747041 , longitude: 34.988099 } // Example: San Francisco*/

  // Add more authorized locations as needed
];

const isAuthorizedLocation = (latitude, longitude) => {
  // Check if the provided latitude and longitude are within a certain range of any authorized location
  return AUTHORIZED_LOCATIONS.some((location) => {
    const distance = Math.sqrt(
      Math.pow(location.latitude - latitude, 2) + Math.pow(location.longitude - longitude, 2)
    );
    return distance < 10; // Adjust the range as needed
  });
};




// Forgot Password Route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Email not found' });
    }

    const user = rows[0];
    const token = crypto.randomBytes(20).toString('hex');
    const tokenExpiry = Date.now() + 3600000; // 1 hour from now

    await pool.query('UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE id = ?', [token, tokenExpiry, user.id]);

    const resetLink = `http://localhost:3000/reset-password/${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the link to reset your password: ${resetLink}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ success: false, message: 'Error sending email' });
      }
      res.json({ success: true, message: 'Password reset email sent' });
    });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Reset Password Route
app.post('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE reset_password_token = ? AND reset_password_expires > ?', [token, Date.now()]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    const user = rows[0];
    const hashedPassword = bcrypt.hashSync(password, 8);
    await pool.query('UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?', [hashedPassword, user.id]);

    res.json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});





// Test Route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Test Database Connection
app.get('/api/test-query', (req, res) => {
  pool.query('SELECT * FROM attendance LIMIT 1', (err, result) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ success: false, message: 'Database query error' });
    }
    console.log('Query result:', result);
    res.json({ success: true, result });
  });
});

// Test Database Connection
app.get('/api/test-db', (req, res) => {
  pool.query('SELECT 1', (err, result) => {
    if (err) {
      console.error('Database test error:', err);
      return res.status(500).json({ success: false, message: 'Database test error' });
    }
    console.log('Database test query executed:', result);
    res.json({ success: true, result });
  });
});



// Record attendance
app.post('/api/attendance', async (req, res) => {
  const attendanceData = req.body;
  try {
    for (const [studentId, status] of Object.entries(attendanceData)) {
      await pool.query('INSERT INTO attendance (user_id, clock_in, clock_out) VALUES (?, NOW(), ?)', [studentId, status]);
    }
    res.send('Attendance recorded successfully');
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Endpoint to get attendance reports
app.get('/api/attendance-reports', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM attendance');
    console.log(rows);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching attendance reports:', err.message);
    res.status(500).json({
      success: false,
      message: 'Server error',
    });
  }
});



// Sign Up Route
app.post('/api/signup', async (req, res) => {
  const { email, password, roleName } = req.body; // Accept roleName instead of role
  console.log("email - " + email);
  console.log("password - " + password);
  
  try {
    // Find the role ID based on the roleName
    const [roleResult] = await pool.query('SELECT id FROM roles WHERE role_name = ?', [roleName]);
    if (roleResult.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid role' });
    }
    const roleId = roleResult[0].id;

    const hashedPassword = bcrypt.hashSync(password, 8);
    const [result] = await pool.query('INSERT INTO users (email, password, role_id) VALUES (?, ?, ?)', [email, hashedPassword, roleId]);
    const userId = result.insertId;
    const token = jwt.sign({ userId: userId, roleId: roleId }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ success: true, token, userId: userId });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Sign up failed' });
  }
});




// Sign In Route
app.post('/api/signin', async (req, res) => {
  console.log("Sign In - Request received");
  const { email, password } = req.body;

  if (!email || !password) {
    console.log("Missing email or password in request");
    return res.status(400).json({ success: false, message: 'Missing email or password' });
  }

  console.log('Received email:', email);
  console.log('Received password:', password);

  try {
    const [rows] = await pool.query('SELECT users.id, users.password, users.role_id, roles.role_name, users.email FROM users JOIN roles ON users.role_id = roles.id WHERE users.email = ?', [email]);
    console.log("Database query executed");
    console.log('Query result:', rows);

    if (rows.length > 0) {
      const user = rows[0];
      console.log('User found:', user);
      const isValidPassword = bcrypt.compareSync(password, user.password);
      console.log('Password validation result:', isValidPassword);

      if (isValidPassword) {
        const token = jwt.sign({ userId: user.id, roleId: user.role_id, roleName: user.role_name }, SECRET_KEY, { expiresIn: '1h' });
        console.log("Sign in successful, token generated");
        console.log("userId" , user.id );
        console.log("userName" , user.userName );
        console.log("roleName" , user.role_name );
        res.json({ success: true, token, userId: user.id, userName: user.email, roleName: user.role_name });
      } else {
        console.log("Password is invalid");
        res.json({ success: false, message: 'Invalid credentials' });
      }
    } else {
      console.log("No user found with the given email");
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});




// Clock In Route
app.post('/api/attendance/clockin', [verifyToken, auditLogMiddleware('clockin')], async (req, res) => {

  console.log('enter to clockin:');
  const { userId, latitude, longitude } = req.body;
  console.log('longitude:', longitude);
  console.log('latitude:', latitude);

  if (!isAuthorizedLocation(latitude, longitude)) {
    return res.status(400).json({ success: false, message: 'Unauthorized location' });
  }

  // Get the current date in YYYY-MM-DD format according to the specified timezone
  const currentDate = moment().tz(process.env.TZ).format().split('T')[0];
  console.log('currentDate:', currentDate);

  // Get the current timestamp according to the specified timezone
  const timestamp = moment().tz(process.env.TZ).format();
  console.log('timestamp:', timestamp);

  try {
    // Check if user has already clocked in today
    const [rows] = await pool.query(
      'SELECT * FROM attendance WHERE user_id = ? AND DATE(clock_in) = ?',
      [userId, currentDate]
    );

    if (rows.length > 0) {
      return res.status(400).json({ success: false, message: 'User has already clocked in today' });
    }

    await pool.query('INSERT INTO attendance (user_id, clock_in, latitude, longitude) VALUES (?, ?, ?, ?)', [userId, timestamp, latitude, longitude]);
    res.json({ success: true, message: 'Clocked in successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});





// Clock Out Route
app.post('/api/attendance/clockout', [verifyToken, auditLogMiddleware('clockout')], async (req, res) => {
  const { userId, latitude, longitude } = req.body;
  if (!isAuthorizedLocation(latitude, longitude)) {
    return res.status(400).json({ success: false, message: 'Unauthorized location' });
  }

  const currentDate = moment().tz(process.env.TZ).format().split('T')[0];
  const timestamp = new Date();

  try {
    // Check if user has clocked in today and not clocked out yet
    const [rows] = await pool.query(
      'SELECT * FROM attendance WHERE user_id = ? AND DATE(clock_in) = ? AND clock_out IS NULL',
      [userId, currentDate]
    );

    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: 'No clock-in record found for today or already clocked out' });
    }

    const clockInTime = new Date(rows[0].clock_in);
    const totalHours = (timestamp - clockInTime) / (1000 * 60 * 60); // Convert milliseconds to hours
    await pool.query('UPDATE attendance SET clock_out = ?, total_hours = ?, latitude = ?, longitude = ? WHERE id = ?', [timestamp, totalHours, latitude, longitude, rows[0].id]);
    res.json({ success: true, message: 'Clocked out successfully', clockOutTime: timestamp, totalHours });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Submit an attendance correction request
app.post('/api/attendance/request-correction', [verifyToken, auditLogMiddleware('request_correction')], async (req, res) => {
  const { userId, attendanceId, requestReason } = req.body;
  const requestDate = moment().tz(process.env.TZ).format();

  try {
    await pool.query('INSERT INTO attendance_correction_requests (user_id, attendance_id, request_reason, request_date) VALUES (?, ?, ?, ?)', 
    [userId, attendanceId, requestReason, requestDate]);
    res.json({ success: true, message: 'Correction request submitted successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Manager: Approve or deny a correction request
app.post('/api/attendance/respond-correction', [verifyToken, auditLogMiddleware('respond_correction')], async (req, res) => {
  const { requestId, status, managerResponse } = req.body;
  const responseDate = moment().tz(process.env.TZ).format();

  if (!['approved', 'denied'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status' });
  }

  try {
    await pool.query('UPDATE attendance_correction_requests SET status = ?, manager_response = ?, response_date = ? WHERE id = ?', 
    [status, managerResponse, responseDate, requestId]);
    res.json({ success: true, message: `Correction request ${status}` });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Get all correction requests for a manager
app.get('/api/attendance/correction-requests', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM attendance_correction_requests WHERE status = "pending"');
    res.json({ success: true, requests: rows });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Route to request leave
app.post('/api/leave/request', verifyToken, async (req, res) => {
  const { userId, startDate, endDate, reason } = req.body;
  try {
    const [result] = await pool.query('INSERT INTO leave_requests (user_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)', [userId, startDate, endDate, reason]);
    res.json({ success: true, message: 'Leave request submitted successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Route for managers to get all leave requests
app.get('/api/leave/requests', [verifyToken, isManager], async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM leave_requests');
    res.json({ success: true, leaveRequests: rows });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Route for managers to approve or deny a leave request
app.post('/api/leave/approve-deny', [verifyToken, isManager], async (req, res) => {
  const { requestId, status } = req.body;
  try {
    await pool.query('UPDATE leave_requests SET status = ? WHERE id = ?', [status, requestId]);
    res.json({ success: true, message: `Leave request ${status}` });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


/***       USERS      */
// Fetch all users
app.get('/api/users', [verifyToken, isAdmin], async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, email, role_id FROM users');
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Fetch all roles
app.get('/api/users/roles', [verifyToken, isAdmin], async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, role_name FROM roles');
    res.json({ success: true, roles: rows });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Update user details
app.put('/api/users/:id', [verifyToken, isAdmin], async (req, res) => {
  const { email } = req.body;
  const { id } = req.params;
  try {
    await pool.query('UPDATE users SET email = ? WHERE id = ?', [email, id]);
    res.json({ success: true, message: 'User details updated successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Update user role
app.put('/api/users/:id/role', [verifyToken, isAdmin], async (req, res) => {
  const { roleId } = req.body;
  const { id } = req.params;
  try {
    await pool.query('UPDATE users SET role_id = ? WHERE id = ?', [roleId, id]);
    res.json({ success: true, message: 'User role updated successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Delete user
app.delete('/api/users/:id', [verifyToken, isAdmin], async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});




// Fetch User Profile Route
app.get('/api/profile', verifyToken, async (req, res) => {
  const userId = req.userId;
  try {
    const [rows] = await pool.query('SELECT id, email FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});



// Update User Profile Route
app.put('/api/profile', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { email, password } = req.body;

  try {
    if (password) {
      const hashedPassword = bcrypt.hashSync(password, 8);
      await pool.query('UPDATE users SET email = ?, password = ? WHERE id = ?', [email, hashedPassword, userId]);
    } else {
      await pool.query('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
    }
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Array to store authorized locations in memory (you can replace this with a database table if needed)
let authorizedLocations = [
  { latitude: 37.7749, longitude: -122.4194 }, // Example: San Francisco
  // Add more authorized locations as needed
];

// Get all authorized locations
app.get('/api/locations', (req, res) => {
  res.json({ locations: authorizedLocations });
});

// Add a new authorized location
app.post('/api/locations', (req, res) => {
  const { latitude, longitude } = req.body;
  authorizedLocations.push({ latitude, longitude });
  res.json({ success: true, message: 'Location added successfully' });
});

// Delete an authorized location
app.delete('/api/locations/:index', (req, res) => {
  const index = parseInt(req.params.index, 10);
  if (index >= 0 && index < authorizedLocations.length) {
    authorizedLocations.splice(index, 1);
    res.json({ success: true, message: 'Location deleted successfully' });
  } else {
    res.status(400).json({ success: false, message: 'Invalid location index' });
  }
});










app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
