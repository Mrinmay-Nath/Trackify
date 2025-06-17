const express = require('express');
const axios = require('axios');
require('dotenv').config();

const router = express.Router();

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = 'llama3-8b-8192';

router.post('/tags', async (req, res) => {
  const { title, description, steps = '' } = req.body;

  if (!title || !description) {
    return res.status(400).json({ error: 'Bug title and description are required.' });
  }

  const prompt = `Identify relevant tags for the following bug report. Return 3 to 5 tags only as a JSON array.\n\nBug Title: "${title}"\nDescription: "${description}"\nSteps to Reproduce: "${steps}"\n\nExample Output: ["UI", "Mobile", "Authentication"]`;

  try {
    const response = await axios.post(
      GROQ_API_URL,
      {
        model: MODEL,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.5,
        max_tokens: 100
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const text = response.data.choices[0].message.content;
    const tags = JSON.parse(text.match(/\[.*?\]/s)[0]);

    res.json({ tags });
  } catch (err) {
    console.error('AI Tagging error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to generate AI tags via Groq' });
  }
});

module.exports = router;
