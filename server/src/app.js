const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', scanRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'CyberGuard API' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler — never leaks stack traces to the client
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(500).json({ error: 'An internal server error occurred' });
});

app.listen(PORT, () => {
  console.log(`CyberGuard server running on http://localhost:${PORT}`);
});
