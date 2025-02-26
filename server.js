const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const port = 4000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage (replace with DB in production)
const users = {}; // { username: { id: Buffer, devices: [] } }

// RP (Relying Party) details
const rpID = 'mex-node.space'; // Use your domain in production
const rpName = 'Passkey Example';
const expectedOrigin = 'https://mex-node.space'; // Adjust to FE origin

// Generate a random Buffer for userID
function generateUserID() {
  return crypto.randomBytes(16); // 16-byte Buffer
}

// Registration: Generate options
app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const userID = generateUserID();
  const user = { id: userID, username, devices: [] };
  users[username] = user; // Store by username for simplicity

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id, // Buffer
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'preferred', // For passkeys
    },
  });

  // Store challenge for verification
  users[username].currentChallenge = options.challenge;

  console.log('Registration Options:', options);
  res.json(options);
});

// Registration: Verify response
app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential required' });
  }

  const user = users[username];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      user.devices.push(verification.registrationInfo);
      delete user.currentChallenge;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Authentication: Generate options
app.post('/auth/options', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const user = users[username];
  if (!user || !user.devices.length) {
    return res.status(404).json({ error: 'User or credentials not found' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.devices.map((device) => ({
      id: device.credentialID, // Buffer
      type: 'public-key',
    })),
    userVerification: 'preferred',
  });

  user.currentChallenge = options.challenge;
  console.log('Auth Options:', options);
  res.json(options);
});

// Authentication: Verify response
app.post('/auth/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential required' });
  }

  const user = users[username];
  if (!user || !user.devices.length) {
    return res.status(404).json({ error: 'User or credentials not found' });
  }

  const authenticator = user.devices.find((device) =>
    device.credentialID.equals(Buffer.from(credential.rawId, 'base64url'))
  );
  if (!authenticator) {
    return res.status(400).json({ error: 'Authenticator not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator,
    });

    if (verification.verified) {
      delete user.currentChallenge;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
