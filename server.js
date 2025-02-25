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
    const randomId = Math.random().toString(36).substring(2, 10);
    const email = `passkey-${randomId}@example.com`;

    let user = users.get(email);
    if (!user) {
        user = {
            id: isoUint8Array.fromUTF8String(email),
            email,
            credentials: []
        };
        users.set(email, user);
    }

    req.session.email = email;

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Biometric THD Service</title>
            <style>
                body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f0f0; }
                .container { text-align: center; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                button { padding: 10px 20px; margin: 10px; border: none; border-radius: 4px; cursor: pointer; }
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
                function base64ToArrayBuffer(base64) {
                    const standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
                    const paddedBase64 = standardBase64.padEnd(standardBase64.length + (4 - standardBase64.length % 4) % 4, '=');
                    const binaryString = window.atob(paddedBase64);
                    const len = binaryString.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    return bytes.buffer;
                }

                function arrayBufferToBase64(buffer) {
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.byteLength; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }

                const email = '${email}';  // Injected by backend

                document.getElementById('yesBtn').addEventListener('click', async () => {
                    try {
                        const response = await fetch('/auth/start-registration', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email })
                        });
                        
                        const options = await response.json();
                        if (!response.ok) throw new Error(options.error || 'Failed to fetch registration options');

                        options.challenge = base64ToArrayBuffer(options.challenge);
                        options.user.id = base64ToArrayBuffer(options.user.id);
                        if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
                            options.excludeCredentials = options.excludeCredentials.map(cred => ({
                                ...cred,
                                id: base64ToArrayBuffer(cred.id)
                            }));
                        } else {
                            options.excludeCredentials = [];
                        }

                        const credential = await navigator.credentials.create({ publicKey: options });

                        const regResponse = {
                            id: credential.id,
                            rawId: arrayBufferToBase64(credential.rawId),
                            response: {
                                clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                                attestationObject: arrayBufferToBase64(credential.response.attestationObject)
                            },
                            type: credential.type
                        };

                        const verifyResponse = await fetch('/auth/verify-registration', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ...regResponse, email })
                        });

                        const result = await verifyResponse.json();
                        if (result.success) {
                            alert('Passkey registration successful!');
                        } else {
                            throw new Error(result.error || 'Verification failed');
                        }
                    } catch (error) {
                        alert('Error during registration: ' + error.message);
                    }
                });

                document.getElementById('noBtn').addEventListener('click', () => {
                    alert('Registration cancelled.');
                });
            </script>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
