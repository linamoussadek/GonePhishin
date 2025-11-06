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

// Register routes
app.use('/api/notary', notaryRoutes);

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

