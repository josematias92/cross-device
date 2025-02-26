const express = require('express');
const bodyParser = require('body-parser');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const port = 3000;

// In-memory storage (replace with a real database in production)
const users = new Map(); // { username: { id: Buffer, credentials: Array } }
const challenges = new Map(); // { username: challenge }

// Middleware
app.use(bodyParser.json());
app.use(express.static('public')); // Serve frontend files from 'public' folder

// Configuration
const rpID = 'localhost'; // Relying Party ID (your domain in production)
const rpName = 'HomeDepot';
const expectedOrigin = 'http://localhost:3000'; // Update for production

// Registration: Generate options
app.get('/register-options', (req, res) => {
  const username = req.query.username || 'user@example.com'; // Simulated user

  // Check if user exists
  if (!users.has(username)) {
    const userId = Buffer.from(crypto.randomUUID().replace(/-/g, ''), 'hex');
    users.set(username, { id: userId, credentials: [] });
  }

  const user = users.get(username);

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: username,
    userDisplayName: 'HomeDepot User',
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'required',
    },
  });

  // Store challenge for verification
  challenges.set(username, options.challenge);

  res.json(options);
});

// Registration: Verify and store passkey
app.post('/register', async (req, res) => {
  const { username = 'user@example.com', response } = req.body;
  const user = users.get(username);

  if (!user || !challenges.has(username)) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  const expectedChallenge = challenges.get(username);

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      // Store the credential
      user.credentials.push(verification.registrationInfo);
      challenges.delete(username); // Clean up
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Registration failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Authentication: Generate options
app.get('/auth-options', (req, res) => {
  const username = req.query.username || 'user@example.com';

  const user = users.get(username);
  if (!user || user.credentials.length === 0) {
    return res.status(400).json({ error: 'No registered passkeys for user' });
  }

  const options = generateAuthenticationOptions({
    rpID,
    allowCredentials: user.credentials.map(cred => ({
      id: cred.credentialID,
      type: 'public-key',
      transports: ['internal', 'hybrid'],
    })),
    userVerification: 'required',
  });

  // Store challenge for verification
  challenges.set(username, options.challenge);

  res.json(options);
});

// Authentication: Verify
app.post('/authenticate', async (req, res) => {
  const { username = 'user@example.com', response } = req.body;
  const user = users.get(username);

  if (!user || !challenges.has(username)) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  const expectedChallenge = challenges.get(username);
  const credential = user.credentials[0]; // Assuming one credential for simplicity

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential,
    });

    if (verification.verified) {
      challenges.delete(username); // Clean up
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during authentication' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
