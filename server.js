const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const port = 4000;

const rpID = 'mex-node.space';
const rpName = 'Passkey Backend';
const expectedOrigin = 'https://mex-node.space';

// Middleware
app.use(express.json());
app.use(cors({
  origin: expectedOrigin,
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage (replace with a database in production)
const users = {}; // { username: { id: Buffer, devices: [{ credentialID, credentialPublicKey, counter, transports }] } }

// Generate a random user ID
function generateUserID() {
  return crypto.randomBytes(16);
}

// Clear all users
app.get('/clear-user', (req, res) => {
  for (const key in users) delete users[key];
  return res.json({ message: 'All users cleared successfully' });
});

// Debug endpoint to inspect credentials
app.get('/debug/credentials/:username', (req, res) => {
  const { username } = req.params;
  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }
  const devices = users[username].devices.map(device => ({
    credentialID: device.credentialID.toString('base64url'),
    counter: device.counter,
    transports: device.transports
  }));
  res.json(devices);
});

// Registration: Generate options
app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  if (users[username]) return res.status(400).json({ error: 'Username already exists' });

  const userID = generateUserID();
  users[username] = { id: userID, username, devices: [] };

  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID,
      userName: username,
      attestationType: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
    });

    users[username].currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Registration options error:', error);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

// Registration: Verify response
app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential are required' });
  }

  const user = users[username];
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }

    const { registrationInfo } = verification;
    if (!registrationInfo || !registrationInfo.credentialID || !registrationInfo.credentialPublicKey) {
      throw new Error('Missing required registration info');
    }

    const device = {
      credentialID: registrationInfo.credentialID,
      credentialPublicKey: registrationInfo.credentialPublicKey,
      counter: registrationInfo.counter ?? 0, // Ensure counter is always a number
      transports: credential.response.transports || ['internal']
    };

    console.log('Storing device:', JSON.stringify(device, null, 2));
    user.devices.push(device);
    delete user.currentChallenge;

    res.json({ verified: true });
  } catch (error) {
    console.error('Registration verification error:', error);
    res.status(500).json({ error: 'Verification error: ' + error.message });
  }
});

// Authentication: Generate options
app.post('/auth/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  const user = users[username];
  if (!user || !user.devices.length) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  try {
    const allowCredentials = user.devices.map(device => ({
      id: device.credentialID.toString('base64url'),
      type: 'public-key',
      transports: device.transports
    }));

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Authentication options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

// Authentication: Verify response
app.post('/auth/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential are required' });
  }

  const user = users[username];
  if (!user || !user.devices.length) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  try {
    console.log('Incoming credential:', JSON.stringify(credential, null, 2));
    console.log('Stored devices:', JSON.stringify(user.devices, null, 2));

    const authenticator = user.devices.find(device => 
      device.credentialID.toString('base64url') === credential.id
    );

    if (!authenticator) {
      console.log('No matching authenticator found for ID:', credential.id);
      return res.status(400).json({ error: 'Passkey not recognized' });
    }

    console.log('Matched authenticator:', JSON.stringify(authenticator, null, 2));

    // Ensure authenticator has all required fields
    if (!authenticator.credentialID || !authenticator.credentialPublicKey || 
        typeof authenticator.counter !== 'number') {
      throw new Error('Invalid authenticator data');
    }

    const authData = {
      credentialID: authenticator.credentialID,
      credentialPublicKey: authenticator.credentialPublicKey,
      counter: authenticator.counter,
      transports: authenticator.transports
    };

    console.log('Verification data:', JSON.stringify(authData, null, 2));

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: authData
    });

    if (verification.verified) {
      authenticator.counter = verification.authenticationInfo.newCounter ?? authenticator.counter;
      delete user.currentChallenge;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Authentication verification failed' });
    }
  } catch (error) {
    console.error('Authentication verification error:', error);
    res.status(500).json({ error: 'Authentication error: ' + error.message });
  }
});

// Default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
