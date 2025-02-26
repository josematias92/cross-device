const express = require('express');
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
app.use(express.json());
app.use(express.static('public')); // Serve static files from 'public' folder

// In-memory storage (replace with a database in production)
const users = {}; // { username: { id: Buffer, devices: [] } }

// Relying Party (RP) configuration
const rpID = 'localhost'; // Use your domain in production
const rpName = 'Simple Passkey App';
const expectedOrigin = 'http://localhost:4000';

// Generate a random user ID
function generateUserID() {
  return crypto.randomBytes(16); // Returns a Buffer
}

// Serve the frontend HTML
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Passkey Demo</title>
    </head>
    <body>
      <h1>Passkey Registration & Authentication</h1>
      <input id="username" type="text" placeholder="Enter username" />
      <button id="registerBtn">Register Passkey</button>
      <button id="authBtn">Authenticate</button>
      <div id="status"></div>

      <script>
        // Convert base64url to ArrayBuffer
        function base64urlToArrayBuffer(base64url) {
          let str = base64url.replace(/-/g, '+').replace(/_/g, '/');
          const padding = str.length % 4;
          if (padding) str += '='.repeat(4 - padding);
          const binary = atob(str);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes.buffer;
        }

        // Convert ArrayBuffer to base64url
        function arrayBufferToBase64url(buffer) {
          const bytes = new Uint8Array(buffer);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
          return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        // Register a passkey
        async function register() {
          const username = document.getElementById('username').value;
          if (!username) return updateStatus('Please enter a username');

          try {
            updateStatus('Fetching registration options...');
            const response = await fetch('/register/options', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username }),
            });
            const options = await response.json();

            options.challenge = base64urlToArrayBuffer(options.challenge);
            options.user.id = base64urlToArrayBuffer(options.user.id);

            updateStatus('Creating passkey...');
            const credential = await navigator.credentials.create({ publicKey: options });

            const credentialResponse = {
              id: credential.id,
              rawId: arrayBufferToBase64url(credential.rawId),
              type: credential.type,
              response: {
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
              },
            };

            updateStatus('Verifying registration...');
            const verifyResponse = await fetch('/register/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, credential: credentialResponse }),
            });
            const result = await verifyResponse.json();

            if (result.verified) {
              updateStatus('Registration successful!', 'green');
            } else {
              updateStatus('Registration failed: ' + (result.error || 'Unknown error'), 'red');
            }
          } catch (error) {
            updateStatus('Error during registration: ' + error.message, 'red');
            console.error(error);
          }
        }

        // Authenticate with a passkey
        async function authenticate() {
          const username = document.getElementById('username').value;
          if (!username) return updateStatus('Please enter a username');

          try {
            updateStatus('Fetching authentication options...');
            const response = await fetch('/auth/options', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username }),
            });
            const options = await response.json();

            options.challenge = base64urlToArrayBuffer(options.challenge);
            options.allowCredentials = options.allowCredentials.map(cred => ({
              ...cred,
              id: base64urlToArrayBuffer(cred.id),
            }));

            updateStatus('Authenticating...');
            const credential = await navigator.credentials.get({ publicKey: options });

            const credentialResponse = {
              id: credential.id,
              rawId: arrayBufferToBase64url(credential.rawId),
              type: credential.type,
              response: {
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
                signature: arrayBufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle
                  ? arrayBufferToBase64url(credential.response.userHandle)
                  : null,
              },
            };

            updateStatus('Verifying authentication...');
            const verifyResponse = await fetch('/auth/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, credential: credentialResponse }),
            });
            const result = await verifyResponse.json();

            if (result.verified) {
              updateStatus('Authentication successful!', 'green');
            } else {
              updateStatus('Authentication failed: ' + (result.error || 'Unknown error'), 'red');
            }
          } catch (error) {
            updateStatus('Error during authentication: ' + error.message, 'red');
            console.error(error);
          }
        }

        // Update status message
        function updateStatus(message, color = 'black') {
          const status = document.getElementById('status');
          status.textContent = message;
          status.style.color = color;
        }

        // Event listeners
        document.getElementById('registerBtn').addEventListener('click', register);
        document.getElementById('authBtn').addEventListener('click', authenticate);
      </script>
    </body>
    </html>
  `);
});

// Registration: Generate options
app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

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
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: 'Failed to generate options' });
  }
});

// Registration: Verify response
app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) return res.status(400).json({ error: 'Missing data' });

  const user = users[username];
  if (!user) return res.status(404).json({ error: 'User not found' });

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
    console.error('Error verifying registration:', error);
    res.status(500).json({ error: 'Verification error' });
  }
});

// Authentication: Generate options
app.post('/auth/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

  const user = users[username];
  if (!user || !user.devices.length) return res.status(404).json({ error: 'User or passkey not found' });

  try {
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.devices.map(device => ({
        id: device.credentialID,
        type: 'public-key',
      })),
      userVerification: 'preferred',
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Error generating auth options:', error);
    res.status(500).json({ error: 'Failed to generate options' });
  }
});

// Authentication: Verify response
app.post('/auth/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) return res.status(400).json({ error: 'Missing data' });

  const user = users[username];
  if (!user || !user.devices.length) return res.status(404).json({ error: 'User or passkey not found' });

  const authenticator = user.devices.find(device =>
    device.credentialID.equals(Buffer.from(credential.rawId, 'base64url'))
  );
  if (!authenticator) return res.status(400).json({ error: 'Passkey not recognized' });

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
    console.error('Error verifying authentication:', error);
    res.status(500).json({ error: 'Verification error' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
