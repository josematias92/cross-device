// server.js
const express = require('express');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const { generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 4000;

// In-memory storage - replace with actual database in production
const users = new Map(); // email -> user data
const challenges = new Map(); // email -> challenge

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set to true in production with HTTPS
}));
app.use(express.static('public')); // Serve static files from 'public' directory

// Configuration
const rpID = 'mex-node.space';
const rpName = 'Passkey Portal';
const origin = `https://mex-node.space`;

// Serve HTML at root endpoint
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Registration Start
app.post('/auth/start-registration', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    let user = users.get(email);
    if (!user) {
        user = {
            id: isoUint8Array.fromUTF8String(email),
            email,
            credentials: []
        };
        users.set(email, user);
    }

    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: email,
        attestationType: 'none',
        excludeCredentials: user.credentials.map(cred => ({
            id: cred.id,
            type: 'public-key'
        })),
        authenticatorSelection: {
            userVerification: 'preferred'
        }
    });

    challenges.set(email, options.challenge);
    req.session.email = email;

    res.json(options);
});

// Registration Verification
app.post('/auth/verify-registration', async (req, res) => {
    const { email, id, rawId, response, type } = req.body;
    const expectedChallenge = challenges.get(email);

    if (!expectedChallenge || !req.session.email || req.session.email !== email) {
        return res.status(400).json({ success: false, error: 'Invalid session or challenge' });
    }

    try {
        const verification = await verifyRegistrationResponse({
            response: { id, rawId, response, type },
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID
        });

        if (verification.verified) {
            const user = users.get(email);
            user.credentials.push({
                id: rawId,
                publicKey: verification.registrationInfo.credentialPublicKey,
                counter: verification.registrationInfo.counter
            });
            users.set(email, user);
            challenges.delete(email);

            res.json({ success: true });
        } else {
            res.status(400).json({ success: false, error: 'Verification failed' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Authentication Start
app.post('/auth/start-authentication', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = users.get(email);
    if (!user || !user.credentials.length) {
        return res.status(404).json({ error: 'User not registered' });
    }

    const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: user.credentials.map(cred => ({
            id: cred.id,
            type: 'public-key'
        })),
        userVerification: 'preferred'
    });

    challenges.set(email, options.challenge);
    req.session.email = email;

    res.json(options);
});

// Authentication Verification
app.post('/auth/verify-authentication', async (req, res) => {
    const { email, id, rawId, response, type } = req.body;
    const expectedChallenge = challenges.get(email);

    if (!expectedChallenge || !req.session.email || req.session.email !== email) {
        return res.status(400).json({ success: false, error: 'Invalid session or challenge' });
    }

    const user = users.get(email);
    if (!user) {
        return res.status(404).json({ success: false, error: 'User not found' });
    }

    const credential = user.credentials.find(cred => cred.id === rawId);
    if (!credential) {
        return res.status(400).json({ success: false, error: 'Credential not found' });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: { id, rawId, response, type },
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: credential.id,
                publicKey: credential.publicKey,
                counter: credential.counter
            }
        });

        if (verification.verified) {
            credential.counter = verification.authenticationInfo.newCounter;
            users.set(email, user);
            challenges.delete(email);

            res.json({ success: true });
        } else {
            res.status(400).json({ success: false, error: 'Verification failed' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/auth/biometric-prompt', async (req, res) => {
    // Generate a random email for this session
    const randomId = Math.random().toString(36).substring(2, 10);
    const email = `passkey-${randomId}@example.com`;

    // Create user if doesn't exist
    let user = users.get(email);
    if (!user) {
        user = {
            id: isoUint8Array.fromUTF8String(email),
            email,
            credentials: []
        };
        users.set(email, user);
    }

    // Store email in session
    req.session.email = email;

    // Serve HTML page
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Biometric THD Service</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f0f0f0;
                }
                .container {
                    text-align: center;
                    padding: 20px;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                button {
                    padding: 10px 20px;
                    margin: 10px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                #yesBtn { background-color: #4CAF50; color: white; }
                #noBtn { background-color: #f44336; color: white; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>You are about to go into the Biometric THD service.</h2>
                <p>Would you like to proceed?</p>
                <button id="yesBtn">Yes</button>
                <button id="noBtn">No</button>
            </div>

            <script>
                document.getElementById('yesBtn').addEventListener('click', async () => {
                    try {
                        // Fetch registration options
                        const response = await fetch('/auth/start-registration', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: '${email}' })
                        });
                        
                        const options = await response.json();
                        if (!response.ok) throw new Error(options.error);

                        // Start WebAuthn registration
                        const credential = await navigator.credentials.create({ publicKey: options });
                        
                        // Send verification
                        const verifyResponse = await fetch('/auth/verify-registration', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                email: '${email}',
                                id: credential.id,
                                rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                                response: {
                                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                    attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
                                },
                                type: credential.type
                            })
                        });

                        const result = await verifyResponse.json();
                        if (result.success) {
                            alert('Passkey registration successful!');
                            // Redirect or update UI as needed
                        } else {
                            alert('Registration failed: ' + result.error);
                        }
                    } catch (error) {
                        alert('Error during registration: ' + error.message);
                    }
                });

                document.getElementById('noBtn').addEventListener('click', () => {
                    alert('Registration cancelled.');
                    // Optionally redirect or close window
                    // window.location.href = '/';
                });
            </script>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
