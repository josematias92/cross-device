const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
// const crypto = require('crypto'); // Add this for Buffer generation
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
app.use(bodyParser.json());

// In-memory storage for user credentials (replace with a database in production)
const users = {};

// Helper function to generate a random buffer for userID
function generateUserID() {
  return crypto.randomBytes(16); // Returns a Buffer
}

// Routes

// Generate registration options
app.post('/generate-registration-options', (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const userID = generateUserID(); // Generate a Buffer userID
  const user = {
    id: userID,
    username,
    devices: [],
  };

  users[userID.toString('base64')] = user;

  const registrationOptions = generateRegistrationOptions({
    rpName: 'WebAuthn Example',
    rpID: 'mex-node.space',
    userID: user.id, // Pass the binary userID
    userName: user.username,
    attestationType: 'none',
  });

  res.json(registrationOptions);
});

// Verify registration response
app.post('/verify-registration', async (req, res) => {
  const { body } = req;
  const user = users[body.userID];

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      credential: body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: 'https://mex-node.space',
      expectedRPID: 'mex-node.space',
    });

    if (verification.verified) {
      user.devices.push(verification.registrationInfo);
      return res.json({ verified: true });
    } else {
      return res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate authentication options
app.post('/generate-authentication-options', (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const user = Object.values(users).find((u) => u.username === username);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const authenticationOptions = generateAuthenticationOptions({
    allowCredentials: user.devices.map((device) => ({
      id: device.credentialID,
      type: 'public-key',
    })),
    userVerification: 'preferred',
  });

  user.currentChallenge = authenticationOptions.challenge;

  res.json(authenticationOptions);
});

// Verify authentication response
app.post('/verify-authentication', async (req, res) => {
  const { body } = req;
  const user = Object.values(users).find((u) => u.devices.some((d) => d.credentialID === body.id));

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      credential: body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: 'https://mex-node.space',
      expectedRPID: 'mex-node.space',
      authenticator: user.devices.find((d) => d.credentialID === body.id),
    });

    if (verification.verified) {
      return res.json({ verified: true });
    } else {
      return res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
