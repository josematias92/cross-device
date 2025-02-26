const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path')

const app = express();
const port = 4000;

// Middleware
app.use(bodyParser.json());

// Configuration
const rpId = 'mex-node.space'; // Update to your domain in production
const rpName = 'PasskeyApp';
const origin = 'https://mex-node.space/'; // Update for production

// In-memory storage (replace with database in production)
const users = new Map(); // { email: { id: Buffer, credentials: [{ id: Buffer, publicKey: Buffer }] } }
const challenges = new Map(); // { email: Buffer }

// Base64url encoding/decoding
const base64urlEncode = (buffer) => Buffer.from(buffer).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const base64urlDecode = (str) => Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
      res.status(500).send('Error loading authentication page');
    }
  });
});

// Registration Options
app.get('/register-options', (req, res) => {
  const email = req.query.email;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  if (!users.has(email)) {
    const userId = crypto.randomBytes(16);
    users.set(email, { id: userId, credentials: [] });
  }

  const user = users.get(email);
  const challenge = crypto.randomBytes(32);
  challenges.set(email, challenge);

  const options = {
    challenge: base64urlEncode(challenge),
    rp: { name: rpName, id: rpId },
    user: {
      id: base64urlEncode(user.id),
      name: email,
      displayName: email.split('@')[0],
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
    timeout: 60000,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'preferred',
    },
    attestation: 'none',
  };

  res.json(options);
});

// Register Passkey
app.post('/register', (req, res) => {
  const { email, response } = req.body;
  const user = users.get(email);
  const expectedChallenge = challenges.get(email);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  try {
    const clientDataJSON = base64urlDecode(response.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    if (clientData.challenge !== base64urlEncode(expectedChallenge)) {
      return res.status(400).json({ error: 'Invalid challenge' });
    }
    if (clientData.origin !== origin) {
      return res.status(400).json({ error: 'Invalid origin' });
    }

    const credentialId = base64urlDecode(response.id);
    const publicKey = base64urlDecode(response.response.attestationObject); // Simplified
    user.credentials.push({ id: credentialId, publicKey });

    challenges.delete(email);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

// Authentication Options
app.get('/auth-options', (req, res) => {
  const email = req.query.email;
  const user = users.get(email);

  if (!email || !user || user.credentials.length === 0) {
    return res.status(400).json({ error: 'User not found or no passkeys' });
  }

  const challenge = crypto.randomBytes(32);
  challenges.set(email, challenge);

  const options = {
    challenge: base64urlEncode(challenge),
    rpId,
    allowCredentials: user.credentials.map(cred => ({
      type: 'public-key',
      id: base64urlEncode(cred.id),
      transports: ['internal', 'hybrid'],
    })),
    userVerification: 'preferred',
    timeout: 60000,
  };

  res.json(options);
});

// Authenticate Passkey
app.post('/authenticate', (req, res) => {
  const { email, response } = req.body;
  const user = users.get(email);
  const expectedChallenge = challenges.get(email);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'User or challenge not found' });
  }

  try {
    const clientDataJSON = base64urlDecode(response.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    if (clientData.challenge !== base64urlEncode(expectedChallenge)) {
      return res.status(400).json({ error: 'Invalid challenge' });
    }
    if (clientData.origin !== origin) {
      return res.status(400).json({ error: 'Invalid origin' });
    }

    const credentialId = base64urlDecode(response.id);
    const credential = user.credentials.find(cred => cred.id.equals(credentialId));
    if (!credential) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    challenges.delete(email);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: 'Authentication failed' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
