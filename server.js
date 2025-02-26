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

setInterval(() => {
    console.log({
        users,
        challenges,
    })
}, 30000)

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
    if (!user) return res.status(404).json({ error: 'User not found' });

    const options = await generateAuthenticationOptions({
        rpID,
        userVerification: 'preferred',
        allowCredentials: user.credentials.map(cred => ({
            id: cred.id,
            type: 'public-key',
            transports: ['usb', 'ble', 'nfc', 'internal']
        }))
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

    try {
        const verification = await verifyAuthenticationResponse({
            response: { id, rawId, response, type },
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: users.get(email).credentials.find(cred => cred.id === rawId)
        });

        if (verification.verified) {
            challenges.delete(email);
            res.json({ success: true });
        } else {
            res.status(400).json({ success: false, error: 'Authentication failed' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/auth/biometric-prompt', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'registerv2.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
