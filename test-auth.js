// Simple test script to verify authentication endpoints are working
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Mock JWT secret for testing
const JWT_SECRET = 'test-secret-key-for-development-only';

// Test register endpoint
app.post('/test/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate token
    const token = jwt.sign({ id: 'test-user-id', email }, JWT_SECRET, { expiresIn: '24h' });
    
    res.status(201).json({
      message: 'User registered successfully (test)',
      user: { id: 'test-user-id', email },
      token
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Test login endpoint
app.post('/test/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Mock password validation (in real app, would check against database)
    const isValid = password === 'testpassword';
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign({ id: 'test-user-id', email }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({
      message: 'Login successful (test)',
      user: { id: 'test-user-id', email },
      token
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Test protected endpoint
app.get('/test/me', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    
    res.json({
      message: 'Authentication successful (test)',
      user: decoded
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Test auth server running on port ${PORT}`);
  console.log('\nTest endpoints:');
  console.log(`POST http://localhost:${PORT}/test/register`);
  console.log(`POST http://localhost:${PORT}/test/login`);
  console.log(`GET http://localhost:${PORT}/test/me`);
});