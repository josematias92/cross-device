const express = require('express');
const crypto = require('crypto');
const path = require('path'); // Add path module
const cors = require('cors');

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

setInterval(() => {
  console.log({users});
}, 20000);

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
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists' });
  }

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
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
  
    try {
      // Add detailed logging of the credential object
      console.log('Incoming credential structure:', JSON.stringify(credential, null, 2));
      
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: user.currentChallenge,
        expectedOrigin,
        expectedRPID: rpID,
      });
  
      // Log the complete verification object to see its structure
      console.log('Complete verification object:', verification);
  
      if (verification.verified) {
        // Log the exact structure of the registration info
        console.log('Registration info:', verification.registrationInfo);
        console.log('Registration info keys:', Object.keys(verification.registrationInfo || {}));

        // Store original values from browser for debugging/comparison
        const originalId = credential.id;
        const originalRawId = credential.rawId;
        
        // Try multiple ways to extract credential data
        let credentialID, credentialPublicKey, counter;
        
        if (verification.registrationInfo) {
          // Standard path
          credentialID = verification.registrationInfo.credentialID;
          credentialPublicKey = verification.registrationInfo.credentialPublicKey;
          counter = verification.registrationInfo.counter || 0;
        }
        
        // If not found, try alternative paths or fallback to client data
        if (!credentialID) {
          if (credential.id && credential.rawId) {
            console.log('Using fallback from client credential data');
            credentialID = Buffer.from(credential.rawId, 'base64url');
          }
        }
        
        if (!credentialPublicKey && verification.registrationInfo) {
          // Try alternative property names that might exist
          credentialPublicKey = verification.registrationInfo.publicKey || 
                                verification.registrationInfo.publicKeyBytes;
        }
        
        // Log extracted values
        console.log('Extracted credential values:');
        console.log('- originalId:', originalId);
        console.log('- originalRawId:', originalRawId);
        console.log('- credentialID present:', !!credentialID);
        console.log('- credentialPublicKey present:', !!credentialPublicKey);
        console.log('- counter:', counter);
        
        // Validate we have the required credential data
        if (!credentialID) {
          console.log('Could not extract credentialID');
          throw new Error('Missing credentialID in verification result');
        }
        
        if (!credentialPublicKey) {
          // For development, you can try using a dummy public key
          console.log('WARNING: Could not extract credentialPublicKey');
          // Uncomment this for testing
          // credentialPublicKey = Buffer.alloc(32); // Create a dummy public key for testing
          throw new Error('Missing credentialPublicKey in verification result');
        }
        
        // Store credential - ensure Buffer conversion for binary data (only once)
        user.devices.push({
          // Convert to Buffer only if not already a Buffer
          credentialID: Buffer.isBuffer(credentialID) ? credentialID : Buffer.from(credentialID),
          credentialPublicKey: Buffer.isBuffer(credentialPublicKey) ? credentialPublicKey : Buffer.from(credentialPublicKey),
          counter: counter || 0,
          transports: credential.response.transports || [],
          // Store original values for comparison/debugging
          originalId,
          originalRawId
        });
        
        // Extra validation to confirm storage
        console.log('Device stored info:');
        console.log('- Device count:', user.devices.length);
        console.log('- credentialID stored as Buffer:', Buffer.isBuffer(user.devices[0].credentialID));
        console.log('- credentialPublicKey stored as Buffer:', Buffer.isBuffer(user.devices[0].credentialPublicKey));
        
        delete user.currentChallenge;
        res.json({ verified: true });
      } else {
        res.status(400).json({ error: 'Verification failed' });
      }
    } catch (error) {
      console.error('Error verifying registration:', error);
      console.error('Error details:', error.message);
      res.status(500).json({ error: 'Verification error: ' + error.message });
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
      return res.status(404).json({ error: 'User or passkey not found' });
    }
  
    try {
      // Enhanced error logging to help diagnose the issue
      console.log(`Generating auth options for user ${username}`);
      console.log(`User has ${user.devices.length} registered device(s)`);
      
      const allowCredentials = user.devices.map(device => {
        // Improved logging
        console.log('Device:', device);
        console.log(`Credential ID exists: ${!!device.credentialID}`);

        if (!device.credentialID) {
          throw new Error('Missing credentialID in stored device');
        }

        // Convert Buffer to base64url string format which is what the library expects
        //const credentialIDBase64 = device.credentialID.toString('base64url');
        //const credentialIDBase64 = Buffer.from(device.credentialID).toString('base64url');
        const credentialIDBase64 = device.credentialID.toString('base64url');
        console.log('Credential ID as base64url:', credentialIDBase64);

        console.log('Original credential ID (hex):', device.credentialID.toString('hex'));
        console.log('Credential ID as base64url:', credentialIDBase64);
        
        return {
          id: credentialIDBase64, // Use base64url string instead of raw Buffer
          type: 'public-key',
          transports: device.transports || ['internal', 'usb', 'ble', 'nfc'],
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
  const { username, credential } = req.body;
  if (!username || !credential) {
    return res.status(400).json({ error: 'Username and credential are required' });
  }

  const user = users[username];
  if (!user || !user.devices.length) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  const authenticator = user.devices.find(device =>
    device.credentialID.equals(Buffer.from(credential.rawId, 'base64url'))
  );
  if (!authenticator) {
    return res.status(400).json({ error: 'Passkey not recognized' });
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
    console.error('Error verifying authentication:', error);
    res.status(500).json({ error: 'Verification error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, "public" ,'index.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
