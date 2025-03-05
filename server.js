const express = require('express');
const crypto = require('crypto');
const path = require('path'); // Add path module
const cors = require('cors');
const qrcode = require('qrcode'); // Use lowercase 'qrcode' for npm package

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const port = 4000;

const rpID = 'mex-node.space'; // Use your domain in production
const rpName = 'Passkey Backend';
const expectedOrigin = 'https://mex-node.space'; 

// Middleware
app.use(express.json());
app.use(cors({
  origin: expectedOrigin,
  credentials: true
}));

// In-memory storage (replace with a database in production)
const users = {}; // { username: { id: Buffer, devices: [] } }
const sessions = {};
const secondaryDevices = {};
const activeSessions = {};

setInterval(() => {
  console.log({users});
  console.log({sessions});
  console.log({secondaryDevices});
}, 20000);

setInterval(() => {
  console.log({activeSessions});
}, 1000)

// Generate a random user ID
function generateUserID() {
  return crypto.randomBytes(16); // Returns a Buffer
}

app.use(express.static(path.join(__dirname, "public")));

app.get('/clear-user', (req, res) => {
    users = {};
    return res.json({ message: 'All users cleared successfully' });
});

app.get('/debug/credentials/:username', (req, res) => {
  const username = req.params.username;
  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const debugInfo = users[username].devices.map(device => ({
    credentialIDHex: device.credentialID.toString('hex'),
    credentialIDBase64: device.credentialID.toString('base64'),
    credentialIDBase64url: device.credentialID.toString('base64url')
  }));
  
  res.json(debugInfo);
});

// Registration: Generate options
app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!users[username]) {
    users[username] = { id: generateUserID(), username, devices: [], passkeys: [] };
  }

  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: users[username].id,
      userName: username,
      attestationType: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
    });

    users[username].currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential are required' });
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
      user.passkeys.push({
        credentialID: Buffer.from(credential.id, 'base64url'),
        credentialPublicKey: verification.registrationInfo.credentialPublicKey,
        counter: verification.registrationInfo.counter,
      });

      delete user.currentChallenge;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error('Error verifying registration:', error);
    res.status(500).json({ error: 'Verification error: ' + error.message });
  }
});

// Authentication: Generate options
app.post('/auth/options', async (req, res) => {
    const { username } = req.body;

    sessions[username] = false

    console.log(sessions, "SESSIONS")
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
  
    const user = users[username];
    if (!user || !user.passkeys.length) {
      return res.status(404).json({ error: 'User or passkey not found' });
    }
  
    try {
      // Enhanced error logging to help diagnose the issue
      console.log(`Generating auth options for user ${username}`);
      console.log(`User has ${user.passkeys.length} registered passkey(s)`);
      
      const allowCredentials = user.passkeys.map(passkey => {
        // Improved logging
        console.log('Passkey:', passkey);
        console.log(`Credential ID exists: ${!!passkey.credentialID}`);

        if (!passkey.credentialID) {
          throw new Error('Missing credentialID in stored passkey');
        }

        const credentialIDBase64 = passkey.credentialID.toString('base64url');
        console.log('Credential ID as base64url:', credentialIDBase64);

        console.log('Original credential ID (hex):', passkey.credentialID.toString('hex'));
        console.log('Credential ID as base64url:', credentialIDBase64);
        
        return {
          id: credentialIDBase64, // Use base64url string instead of raw Buffer
          type: 'public-key',
          transports: passkey.transports || ['internal', 'usb', 'ble', 'nfc'],
        };
      });
      
      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials,
        userVerification: 'preferred',
        timeout: 60000, // Increase timeout to 1 minute
      });
  
      user.currentChallenge = options.challenge;
      res.json(options);
    } catch (error) {
      // More detailed error logging
      console.error('Error generating authentication options:', error);
      console.error('Error details:', error.message);
      res.status(500).json({ error: 'Failed to generate authentication options' });
    }
});

// Authentication: Verify response
app.post('/auth/verify', async (req, res) => {
  const { username, credential, secondaryDeviceDetails, session } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential are required' });
  }
  
  secondaryDevices[username] = {secondaryDeviceDetails}
  
  let activeSessionVerified = false;
  if(!!activeSessions[username] && activeSessions[username].length > 0) {
    console.log(activeSessions[username], session, "1STORED & 2Payload")
    console.log("Session verification:", activeSessions[username] === session)
    if(activeSessions[username].includes(session)) {
      activeSessionVerified = true
      activeSessions[username] = true
    }
  }

  const user = users[username];
  if (!user || !user.passkeys.length) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  try {
    console.log('Full authentication credential:', JSON.stringify(credential, null, 2));
    console.log('Current challenge:', user.currentChallenge);

    let matches = false;
    const authenticator = user.passkeys.find(passkey => {
      matches = passkey.credentialID.equals(Buffer.from(credential.id, 'base64url'));
      console.log(`Comparing: ${passkey.credentialID.toString('base64url')} with ${credential.id}, matches: ${matches}`);
      sessions[username] = true
      return matches;
    });

    if (!authenticator) {
      console.log('No matching authenticator found');
      return res.status(400).json({ error: 'Passkey not recognized' });
    }

    if (activeSessionVerified !== true) {
      return res.status(400).json({ error: 'Expired Session or Invalid Session' });
    }

    if (matches && activeSessionVerified) {
      delete user.currentChallenge;
      res.json({ verified: true, secondaryDevice: secondaryDeviceDetails });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error('Error verifying authentication:', error);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      error: 'Authentication error: ' + error.message,
      suggestion: 'Please try registering a new passkey'
    });
  }
});

// New endpoint to generate QR code
app.get('/generate-qr', async (req, res) => {
  const email = req.query.email;
  const session = req.query.session;

  activeSessions[email] = [];
  activeSessions[email].push(session);

  setTimeout(() => {
    delete activeSessions[email]
  }, 30000)

  const baseUrl = 'https://mex-node.space/cool';
  const qrUrl = `${baseUrl}?email=${email}&session=${session}`;
  
  // Hardcoded URL
  
  try {
    // Generate QR code as a data URL (base64 PNG)
    const qrCodeDataUrl = await qrcode.toDataURL(qrUrl, {
      width: 150,
      color: { dark: '#f97316', light: '#ffffff' }, // Home Depot orange
    });
    res.json({ qrCode: qrCodeDataUrl });
  } catch (error) {
    console.error('QR Code generation error:', error);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

app.get('/shouldIContinue', async (req, res) => {
  const email = req.query.email;
  
  try {
      if(!!sessions[email] && sessions[email] === true && activeSessions[email] === true ) {
        delete activeSessions[email]
        res.status(200).json({success: true, secondary: secondaryDevices[email] })
      } else {
        res.status(401).json({ error: 'Not yet' });
      }
      
    } catch (error) {
      console.error('Something wrong', error);
      res.status(401).json({ error: 'Not quite' });
    }
});

app.get('/success', async (req, res) => {
  
  try {
     res.sendFile(path.join(__dirname, "public" ,'success.html'));
    } catch (error) {
      console.error('Something wrong', error);
      res.status(401).json({ error: 'Not quite' });
    }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, "public" ,'indexRev.html'));
});

app.get('/cool', (req, res) => {
  res.sendFile(path.join(__dirname, "public" ,'authentication.html'));
});

app.get('/usersLocation', (req, res) => {
  res.sendFile(path.join(__dirname, "public" ,'usersLocation.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
