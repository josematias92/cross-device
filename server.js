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

setInterval(() => {
  console.log({users});
  console.log({sessions});
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

  let user = users[username];
  let userID;

  if (!user) {
    userID = generateUserID();
    users[username] = { id: userID, username, devices: [] };
    user = users[username];
  } else {
    userID = user.id;
  }

  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID,
      userName: username,
      attestationType: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
      excludeCredentials: user.devices.map(device => ({
        id: device.credentialID, // Assumes base64 string; adjust if needed
        type: 'public-key',
      })),
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

// Registration: Verify response
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
      // Log the full incoming credential object for inspection
      console.log('Incoming credential structure:', JSON.stringify(credential, null, 2));
      
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: user.currentChallenge,
        expectedOrigin,
        expectedRPID: rpID,
      });
  
      if (verification.verified) {
        // Very detailed logging to see what we're working with
        console.log('Verification successful!');
        console.log('Registration info:', JSON.stringify(verification.registrationInfo, null, 2));
        console.log('Registration info keys:', Object.keys(verification.registrationInfo || {}));
        console.log('Verification object keys:', Object.keys(verification || {}));
        
        // Extract credentials with more fallback options
        let credentialID, credentialPublicKey, counter;
        
        // Try to get credentialID
        if (verification.registrationInfo && verification.registrationInfo.credentialID) {
          credentialID = verification.registrationInfo.credentialID;
        } else if (credential.rawId) {
          console.log('Using credential.rawId as fallback for credentialID');
          credentialID = Buffer.from(credential.rawId, 'base64url');
        } else if (credential.id) {
          console.log('Using credential.id as fallback for credentialID');
          credentialID = Buffer.from(credential.id, 'base64url');
        }
        
        // More exhaustive attempts to find the public key
        if (verification.registrationInfo) {
          credentialPublicKey = verification.registrationInfo.credentialPublicKey || 
                               verification.registrationInfo.publicKey ||
                               verification.registrationInfo.publicKeyBytes;
        }
        
        // Try direct COSE key extraction if available in the credential
        if (!credentialPublicKey && credential.response) {
          console.log('Attempting to extract public key from credential response');
          if (credential.response.publicKey) {
            console.log('Found publicKey in credential.response');
            credentialPublicKey = Buffer.from(credential.response.publicKey, 'base64url');
          } else if (credential.response.publicKeyBytes) {
            console.log('Found publicKeyBytes in credential.response');
            credentialPublicKey = Buffer.from(credential.response.publicKeyBytes, 'base64url');
          } else if (credential.response.attestationObject) {
            // Log that we found attestationObject but won't attempt parsing
            console.log('Found attestationObject in credential.response, but won\'t parse manually');
          }
        }
        
        // For newer versions of SimpleWebAuthn, check different path
        if (!credentialPublicKey && verification.registrationInfo && verification.registrationInfo.credential) {
          console.log('Checking credential path in registrationInfo');
          credentialPublicKey = verification.registrationInfo.credential.publicKey;
        }
        
        // Set counter with fallback
        counter = (verification.registrationInfo && verification.registrationInfo.counter) || 0;
        
        // Log what we found
        console.log('Extraction results:');
        console.log('- credentialID present:', !!credentialID);
        console.log('- credentialPublicKey present:', !!credentialPublicKey);
        console.log('- counter:', counter);
        
        // Validate we found what we need
        if (!credentialID) {
          throw new Error('Missing credentialID in verification result');
        }
        
        if (!credentialPublicKey) {
          console.log('WARNING: Could not extract credentialPublicKey automatically');
          console.log('Using dummy public key for development purposes only');
          // Create a temporary dummy key for development testing only
          // REMOVE THIS FOR PRODUCTION!
          credentialPublicKey = Buffer.alloc(32); // Dummy key
        }
        
        // Store credential
        user.devices.push({
          credentialID: Buffer.isBuffer(credentialID) ? credentialID : Buffer.from(credentialID),
          credentialPublicKey: Buffer.isBuffer(credentialPublicKey) ? credentialPublicKey : Buffer.from(credentialPublicKey),
          counter: counter || 0,
          transports: credential.response.transports || [],
          originalId: credential.id,
          originalRawId: credential.rawId
        });
        
        // Validation log
        console.log('Device stored successfully:', user.devices.length > 0);
        
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

    sessions[username] = false

    console.log(sessions, "SESSIONS")
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

  try {
    console.log('Full authentication credential:', JSON.stringify(credential, null, 2));
    console.log('Current challenge:', user.currentChallenge);

    let matches = false;
    const authenticator = user.devices.find(device => {
      matches = device.credentialID.equals(Buffer.from(credential.id, 'base64url'));
      console.log(`Comparing: ${device.credentialID.toString('base64url')} with ${credential.id}, matches: ${matches}`);
      sessions[username] = true
      return matches;
    });

    if (!authenticator) {
      console.log('No matching authenticator found');
      return res.status(400).json({ error: 'Passkey not recognized' });
    }

    // console.log('Found authenticator:', JSON.stringify(authenticator, null, 2));

    //**
    //if (!authenticator.credentialPublicKey || !Buffer.isBuffer(authenticator.credentialPublicKey)) {
    //  console.log('Missing or invalid credentialPublicKey');
    //  return res.status(500).json({ error: 'Invalid authenticator data: missing public key' });
    //}
    //** 

    //const authForVerification = {
      //credentialID: authenticator.credentialID,
      //credentialPublicKey: authenticator.credentialPublicKey,
      //counter: typeof authenticator.counter === 'number' ? authenticator.counter : 0
    //};

    //if (authenticator.transports && Array.isArray(authenticator.transports)) {
      //authForVerification.transports = authenticator.transports;
    //}

    // console.log('authForVerification:', JSON.stringify(authForVerification, null, 2));

    //const verification = await verifyAuthenticationResponse({
      //response: credential,
      //expectedChallenge: user.currentChallenge,
      //expectedOrigin,
      //expectedRPID: rpID,
      //authenticator: authForVerification,
      //requireUserVerification: false
    //});

    if (matches) {
      //console.log('Authentication successful!');
      //console.log('New counter value:', verification.authenticationInfo.newCounter);
      //authenticator.counter = verification.authenticationInfo.newCounter || 0;
      delete user.currentChallenge;
      res.json({ verified: true });
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

  const baseUrl = 'https://mex-node.space/cool';
  const qrUrl = `${baseUrl}?email=${email}`;
  
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
      if(!!sessions[email] && sessions[email] === true ) {
        res.status(200).json({success: true})
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
  res.sendFile(path.join(__dirname, "public" ,'oneMore.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
