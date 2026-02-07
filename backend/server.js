const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { analyzeUrl } = require('./analyzer');

const app = express();
const PORT = process.env.PORT || 3000;



// Middleware
app.use(cors());
app.use(express.json());

// Main Analysis Endpoint
app.post('/analyze', async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Run analysis
        const result = await analyzeUrl(url);

        // Return result
        res.json(result);

    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            details: error.message
        });
    }
});

// Health check
app.get('/', (req, res) => {
    res.send('TheOcean Safe-Scan Lite Backend is running.');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OpenAI Integration: ${process.env.OPENAI_API_KEY ? 'Enabled' : 'Disabled (using fallback)'}`);
});
