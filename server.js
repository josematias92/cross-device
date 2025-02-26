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

app.use(express.json());

const users = {};
const rpID = 'localhost';
const rpName = 'Simple Passkey App';
const expectedOrigin = 'http://localhost:4000';

function generateUserID() {
  return crypto.randomBytes(16);
}

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
        function base64urlToArrayBuffer(base64url) {
          let str = base64url.replace(/-/g, '+').replace(/_/g, '/');
          const padding = str.length % 4;
          if (padding) str += '='.repeat(4 - padding);
          const binary = atob(str);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes.buffer;
        }

        function arrayBufferToBase64url(buffer) {
          const bytes = new Uint8Array(buffer);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
          return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        async function register() {
          const username = document.getElementById('username').value;
          if (!username) return updateStatus('Please enter a username');
          // ... (rest of the original register function)
        }

        async function authenticate() {
          const username = document.getElementById('username').value;
          if (!username) return updateStatus('Please enter a username');
          // ... (rest of the original authenticate function)
        }

        function updateStatus(message, color = 'black') {
          const status = document.getElementById('status');
          status.textContent = message;
          status.style.color = color;
        }

        document.getElementById('registerBtn').addEventListener('click', register);
        document.getElementById('authBtn').addEventListener('click', authenticate);
      </script>
    </body>
    </html>
  `);
});

// ... (rest of the original endpoints unchanged)

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
