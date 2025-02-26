const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = 4000;

// Middleware
app.use(bodyParser.json());
app.use(express.static('public')); // Serve frontend files from 'public' folder

// Configuration
const rpId = 'mex-node.space'; // Relying Party ID (your domain in production)
const rpName = 'HomeDepot';
const origin = 'https://mex-node.space/'; // Update for production

// In-memory storage (replace with a database in production)
const users = new Map(); // { username: { id: Buffer, credentials: [{ id: Buffer, publicKey: Buffer }] } }
const challenges = new Map(); // { username: string }

// Utility to base64url encode/decode
const base64url = {
  encode: (buffer) => Buffer.from(buffer).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
  decode: (str) => Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
};

// Registration: Generate options
app.get('/register-options', (req, res) => {
  const username = req.query.username || 'user@example.com';

  // Create user if not exists
  if (!users.has(username)) {
    const userId = crypto.randomBytes(16); // 16-byte user ID
    users.set(username, { id: userId, credentials: [] });
  }

  const user = users.get(username);
  const challenge = crypto.randomBytes(32); // 32-byte challenge
  challenges.set(username, challenge);

  const options = {
    challenge: base64url.encode(challenge),
    rp: {
      name: rpName,
      id: rpId,
    },
    user: {
      id: base64url.encode(user.id),
      name: username,
      displayName: 'HomeDepot User',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 }, // RS256 (optional, broader support)
    ],
    timeout: 60000,
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // Passkeys prefer platform
      requireResidentKey: true, // Passkey requirement
      userVerification: 'required', // Enforce biometric/PIN
    },
    attestation: 'none', // No attestation for simplicity
  };

  res.json(options);
});

// Registration: Verify and store passkey
app.post('/register', (req, res) => {
  const { username = 'user@example.com', response } = req.body;
  const user = users.get(username);
  const expectedChallenge = challenges.get(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  try {
    // Decode client data
    const clientDataJSON = base64url.decode(response.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    // Verify challenge and origin
    if (clientData.challenge !== base64url.encode(expectedChallenge)) {
      throw new Error('Challenge mismatch');
    }
    if (clientData.origin !== origin) {
      throw new Error('Origin mismatch');
    }

    // Decode authenticator data
    const authData = base64url.decode(response.response.authenticatorData);
    const publicKey = base64url.decode(response.response.attestationObject); // Simplified; real parsing needed

    // Store credential (in production, parse attestationObject properly)
    const credentialId = base64url.decode(response.id);
    user.credentials.push({
      id: credentialId,
      publicKey: publicKey, // Store raw public key (simplified)
    });

    challenges.delete(username); // Clean up
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Registration failed: ' + error.message });
  }
});

// Authentication: Generate options
app.get('/auth-options', (req, res) => {
  const username = req.query.username || 'user@example.com';
  const user = users.get(username);

  if (!user || user.credentials.length === 0) {
    return res.status(400).json({ error: 'No registered passkeys for user' });
  }

  const challenge = crypto.randomBytes(32);
  challenges.set(username, challenge);

  const options = {
    challenge: base64url.encode(challenge),
    rpId,
    allowCredentials: user.credentials.map(cred => ({
      type: 'public-key',
      id: base64url.encode(cred.id),
      transports: ['internal', 'hybrid'],
    })),
    userVerification: 'required',
    timeout: 60000,
  };

  res.json(options);
});

// Authentication: Verify
app.post('/authenticate', (req, res) => {
  const { username = 'user@example.com', response } = req.body;
  const user = users.get(username);
  const expectedChallenge = challenges.get(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  try {
    // Decode client data
    const clientDataJSON = base64url.decode(response.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    // Verify challenge and origin
    if (clientData.challenge !== base64url.encode(expectedChallenge)) {
      throw new Error('Challenge mismatch');
    }
    if (clientData.origin !== origin) {
      throw new Error('Origin mismatch');
    }

    // Verify credential ID exists
    const credentialId = base64url.decode(response.id);
    const credential = user.credentials.find(cred => cred.id.equals(credentialId));
    if (!credential) {
      throw new Error('Credential not found');
    }

    // In production: Verify signature with public key (simplified here)
    const authData = base64url.decode(response.response.authenticatorData);
    const signature = base64url.decode(response.response.signature);

    // Basic verification (signature check omitted for simplicity)
    challenges.delete(username);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Authentication failed: ' + error.message });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
