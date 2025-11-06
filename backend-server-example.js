// Example server.js file showing how to register the notary route
// This file is for reference - your actual server.js should be in your backend directory

const express = require('express');
const cors = require('cors');
require('dotenv').config(); // Load .env file

const app = express();
const PORT = process.env.SERVER_PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Import routes
const notaryRoutes = require('./routes/notary');
// Add other routes as needed:
// const urlscanRoutes = require('./routes/urlscan');
// const authRoutes = require('./routes/auth');

// Register routes
app.use('/api/notary', notaryRoutes);
// app.use('/api/urlscan', urlscanRoutes);
// app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Notary endpoint: http://localhost:${PORT}/api/notary/observe`);
  console.log(`💚 Health check: http://localhost:${PORT}/health`);
});

