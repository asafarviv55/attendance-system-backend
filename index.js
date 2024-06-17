const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./config/db'); // Import the database connection
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { verifyToken,isAdmin, isManager } = require('./middleware/auth');


const app = express();
const port = 5000;

app.use(bodyParser.json());
app.use(cors()); // Enable CORS for all routes
const SECRET_KEY = "asaf1984arviv";
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

// Fetch students
app.get('/api/students', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM students');
    console.log(rows);
    res.json(rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
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
    const [rows] = await pool.query('SELECT users.id, users.password, users.role_id, roles.role_name FROM users JOIN roles ON users.role_id = roles.id WHERE users.email = ?', [email]);
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
        res.json({ success: true, token, userId: user.id, roleName: user.role_name });
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
app.post('/api/attendance/clockin', (req, res) => {
  console.log('backend clockin :');
  const { userId } = req.body;
  console.log('backend clockin userId:', userId);
  if (!userId) {
    return res.status(400).json({ success: false, message: 'User ID is required' });
  }
  const timestamp = new Date();
  pool.query('INSERT INTO attendance (user_id, clock_in) VALUES (?, ?)', [userId, timestamp], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
    return res.json({ success: true, message: 'Clocked in successfully' });
  });
});




app.post('/api/attendance/clockout', async (req, res) => {
  console.log('Clock Out Request:', req.body); // Log request body for debugging
  const { userId } = req.body;
  console.log('userId:', userId);
  const timestamp = new Date();
  const [rows] = await pool.query('SELECT clock_in FROM attendance WHERE user_id = ? AND clock_out IS NULL', [userId] );
    console.log('Executing SELECT query');
    if (rows.length == 0) {
    //  console.log('Database errors:', err);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
    if (rows.length > 0) {
      console.log('rows.length:', rows.length);
      const clockInTime = new Date(rows[0].clock_in);
      console.log('clockInTime:', clockInTime);
      const totalHours = (timestamp - clockInTime) / (1000 * 60 * 60); // Convert milliseconds to hours
      console.log('Total hours:', totalHours);
      pool.query('UPDATE attendance SET clock_out = ?, total_hours = ? WHERE user_id = ? AND clock_out IS NULL', [timestamp, totalHours, userId], (err, updateResult) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ success: false, message: 'Internal server error' });
        }
        console.log('Update result:', updateResult);
        res.json({ success: true, message: 'Clocked out successfully', clockOutTime: timestamp, totalHours });
      });
    } else {
      console.log('No clock-in record found for user');
      res.status(400).json({ success: false, message: 'No clock-in record found for user' });
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


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
