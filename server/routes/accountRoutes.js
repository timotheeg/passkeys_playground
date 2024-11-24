import { Router } from 'express';
import db from '../db.js';
import crypto from 'crypto';
import { decode as cborDecode } from 'cbor2';

const router = Router();

// define error handler last
router.use((err, req, res, next) => {
    console.error('Error occurred:', err);

    // Respond with a generic error message
    res.status(err.status || 500).json({
        error: {
            message: err.message || 'Internal Server Error',
        },
    });
});


// application constants
const SERVER_ORIGIN = 'http://localhost:3000';
const RP_ID = 'localhost';
const RP_NAME = 'passkey_workshop.org';

const FLAG_USER_PRESENCE = 0x01;

// verify session
function isLoggedIn(req, res, next) {
    if (!req.session?.user?.uuid) {
        res.sendStatus(401);
        return;
    }
    console.log('Valid Session found');
    next();
}


router.post('/', async (req, res) => {
    const { username } = req.body;

    try {
        const uuid = crypto.randomUUID();

        await db.run(
            `INSERT INTO users (uuid, username, display_name) VALUES (?, ?, ?)`,
            [uuid, username, username]
        );

        const user = {
            uuid,
            username, 
        }

        req.session.user = user;

        await req.session.saveAsync();

        res.status(201).json({
            user
        });
    }
    catch(err) {
        console.error(err.message);
        res.sendStatus(500);
    }
});

router.post('/register-options', isLoggedIn, async (req, res) => {
    const user = await db.get(`SELECT * from users where uuid=?`, [req.session.user.uuid]);

    const challenge = crypto.randomBytes(32);
    const challengeB64 = challenge.toString('base64');

    req.session.reg_challenge = challengeB64;

    res.json({
        challenge: challengeB64,
        rp: { 
            id: RP_ID,
            name: RP_NAME,
        },
        user: {
            id: user.uuid,
            name: user.username,
            displayName: user.display_name,
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 }, // ES256
            { type: "public-key", alg: -257 }, // RS256
        ],
        timeout: 60000,
        attestation: "direct", // Enforce attestation signature
        authenticatorSelection: { userVerification: "required" }
    });
});

function decodeAttestationObject(attestationObjectBase64) {
    const decoded = cborDecode(Buffer.from(attestationObjectBase64, 'base64'));

    console.log({func: 'decodeAttestationObject', decoded});

    // Extract relevant fields
    const { authData, fmt, attStmt } = decoded;

    return {
        authenticatorData: authData,
        format: fmt,
        attestationStatement: attStmt,
    };
}

function extractPublicKey(authenticatorData) {
    const rpIdHash = authenticatorData.slice(0, 32); // First 32 bytes
    const flags = authenticatorData[32]; // 1 byte for flags
    const signCount = authenticatorData.readUInt32BE(33); // Next 4 bytes (big-endian)
    const attestedCredentialData = authenticatorData.slice(37); // Remaining bytes

    // Parse attested credential data
    const aaguid = attestedCredentialData.slice(0, 16); // First 16 bytes
    const credentialIdLength = attestedCredentialData.readUInt16BE(16); // Next 2 bytes
    const credentialId = attestedCredentialData.slice(18, 18 + credentialIdLength); // Extract ID
    const publicKeyBytes = attestedCredentialData.slice(18 + credentialIdLength); // Remainder is public key

    return {
        rpIdHash,
        flags,
        signCount,
        aaguid,
        credentialId,
        publicKeyBytes,
    };
}

function coseToDer(coseKey) {
    const COSE_KEYS = {
        kty: 1, // Key Type
        alg: 3, // Algorithm
        crv: -1, // Curve
        x: -2, // X-coordinate
        y: -3, // Y-coordinate (for EC keys, optional in WebAuthn)
    };

    const coseStruct = cborDecode(coseKey);

    if (coseStruct.get(COSE_KEYS.kty) !== 2 || coseStruct.get(COSE_KEYS.alg) !== -7) {
        throw new Error('Unsupported key type or algorithm. Expected EC key with alg -7.');
    }

    const x = coseStruct.get(COSE_KEYS.x);
    const y = coseStruct.get(COSE_KEYS.y);

    // Create an ASN.1 EC public key in DER format
    const derHeader = Buffer.from([
        0x30, 0x59, // SEQUENCE
        0x30, 0x13, // SEQUENCE
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID for EC
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID for P-256 curve
        0x03, 0x42, 0x00, // BIT STRING
    ]);

    const publicKeyBuffer = Buffer.concat([
        Buffer.from([0x04]), // Uncompressed point indicator
        Buffer.from(x), // X-coordinate
        Buffer.from(y), // Y-coordinate
    ]);

    return Buffer.concat([derHeader, publicKeyBuffer]);
}

function verifySignature(publicKeyBytes, authenticatorData, clientDataJSON, signature) {
    // Hash clientDataJSON to get clientDataHash
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();

    // Concatenate authenticatorData and clientDataHash
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    // Convert COSE-encoded public key to DER format
    const publicKeyDer = coseToDer(publicKeyBytes);

    // Import the public key using WebCrypto-like format
    const publicKey = crypto.createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'spki',
    });

    // Verify the signature
    const isValid = crypto.verify(
        null, // Default signing algorithm (ECDSA in this case)
        signedData, // Data to verify
        publicKey, // Public key
        signature // Signature from attestation
    );

    return isValid;
}

async function validatePasskeyRegistration(attestationObject, clientDataJSONBuffer) {
    // Decode attestationObject
    const { authenticatorData, attestationStatement } = attestationObject;

    // Extract public key
    const publicKey = extractPublicKey(authenticatorData);

    console.log(attestationObject);
    console.log(publicKey);
    console.log({
        encoded: publicKey.publicKeyBytes.toString('base64')
    })

    // Verify the signature
    const isSignatureValid = verifySignature(
        publicKey.publicKeyBytes,
        authenticatorData,
        clientDataJSONBuffer,
        attestationStatement.sig // The signature from the attestation statement
    );

    if (!isSignatureValid) {
        throw new Error('Signature validation failed');
    }

    console.log('Passkey registration is valid!');
}


router.post('/register', isLoggedIn, async (req, res) => {
    const user = req.session.user;
    const expectedChallenge = Buffer.from(req.session.reg_challenge, 'base64');
    const payload = req.body;

    // Decode clientDataJSON
    const clientDataJSONBuffer = Buffer.from(payload.response.clientDataJSON, 'base64');
    const clientData = JSON.parse(clientDataJSONBuffer.toString('utf8'));
    
    console.log({
        payload,
        rawId: {
            encoded: payload.rawId,
            raw: Buffer.from(payload.rawId, 'base64'),
        },
        expectedChallenge: {
            encoded: req.session.reg_challenge,
            raw: expectedChallenge,
        },
        clientData,
        rawChallenge: Buffer.from(clientData.challenge, 'base64'),
    });

    // Validate challenge
    // We validate by comparing the binary buffers to guard against the possibly disjointed base64 and base64url encodings T_T
    if (!Buffer.from(clientData.challenge, 'base64').equals(expectedChallenge)) {
        throw new Error('Challenge mismatch!');
    }
    
    // Validate origin
    if (clientData.origin !== SERVER_ORIGIN) {
        throw new Error('Origin mismatch!');
    }
    
    const attestationObject = decodeAttestationObject(payload.response.attestationObject);
    const publicKey = extractPublicKey(attestationObject.authenticatorData);

    // Validate RawId matches
    if (!Buffer.from(publicKey.credentialId, 'base64').equals(Buffer.from(payload.rawId, 'base64'))) {
        throw new Error('RawId mismatch!');
    }


    if (attestationObject.format != 'none') {
        validatePasskeyRegistration(
            attestationObject,
            clientDataJSONBuffer
        );
    }

    // We're good!! -- all validation passed!
    const signCount = attestationObject.authenticatorData.readUInt32BE(33);

    await db.run(
        `INSERT INTO credentials
        (user_uuid, credential_id, public_key, sign_count)
        VALUES
        (?, ?, ?, ?)`,
        [
            user.uuid,
            publicKey.credentialId.toString('base64'),
            publicKey.publicKeyBytes.toString('base64'),
            signCount
        ]
    );

    req.session.destroy();

    res.json({ success: true });
});

router.post('/login-options', async (req, res) => {
    console.log('/login-options');

    const { username } = req.body;

    const user = await db.get(`
        SELECT uuid, username, display_name FROM users
        WHERE users.username = ?`
        , [username]
    );

    if (!user) {
        return res.status(400).json({ error: "User not found" });
    }

    const credentials = await db.all(`
        SELECT credential_id FROM credentials
        WHERE user_uuid = ?`
        , [user.uuid]
    );

    if (!credentials || credentials.length <= 0) {
        return res.status(404).json({ error: "No PassKey found" });
    }

    const challenge = crypto.randomBytes(32);
    const challengeB64 = challenge.toString('base64');

    req.session.maybe_user = {
        uuid: user.uuid,
        username,
    }

    req.session.login_challenge = challengeB64;

    res.json({
        challenge: challengeB64,
        allowCredentials: credentials.map(cred => ({
            id: cred.credential_id,
            type: 'public-key'
        })),
        timeout: 60000,
        userVerification: "required"
    });
});

router.post('/login', async (req, res) => {
    // validate context
    if (!req.session.maybe_user?.uuid || !req.session.login_challenge) {
        return res.status(404).json({ error: "No ongoing login attempt" });
    }

    const payload = req.body;

    console.log(req.body);

    const selectedCredential = Buffer.from(payload.rawId, 'base64');

    const credential = await db.get(`
        SELECT user_uuid, credential_id, public_key, sign_count FROM credentials
        WHERE user_uuid = ? AND credential_id = ?`
        ,
        [
            req.session.maybe_user.uuid,
            selectedCredential.toString('base64'),
        ]
    );

    if (!credential) {
        return res.status(400).json({ error: "Credential id not found" }); // 404? 🤔
    }

    const storedSignCount = credential.sign_count;
    const expectedChallenge = Buffer.from(req.session.login_challenge, 'base64');

    // The login challenge is single use
    // Any error will need to restart the flow
    delete req.session.login_challenge;

    // Decode clientDataJSON
    const clientDataJSON = Buffer.from(payload.response.clientDataJSON, 'base64')
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));

    // Step 1: Validate clientDataJSON
    if (clientData.type !== "webauthn.get") {
        return res.status(400).json({ error: "Invalid type in clientDataJSON." });
    }
    if (!Buffer.from(clientData.challenge, 'base64').equals(expectedChallenge)) {
        return res.status(400).json({ error: "Challenge mismatch." });
    }
    if (clientData.origin !== SERVER_ORIGIN) {
        return res.status(400).json({ error: "Origin mismatch." });
    }

    // Step 2: Decode authenticatorData
    const authenticatorData = Buffer.from(payload.response.authenticatorData, 'base64');
    const rpIdHash = authenticatorData.subarray(0, 32);
    const flags = authenticatorData[32];
    const signCount = authenticatorData.readUInt32BE(33);

    // Validate RP ID hash
    const expectedRpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
    if (!rpIdHash.equals(expectedRpIdHash)) {
        return res.status(400).json({ error: "RP ID hash mismatch." });
    }

    // Check user presence (UP) flag
    if ((flags & FLAG_USER_PRESENCE) === 0) {
        return res.status(401).json({ error: "User not present." });
    }

    // validate signCount (IF NECESSARY)
    do {
        if (signCount === 0 && storedSignCount === 0) break;
        if (signCount <= storedSignCount) {
            return res.status(400).json({ error: "Sign count validation failed. Possible cloned authenticator." });
        }
    }
    while(false);

    // Step 3: Verify signature
    if (!verifySignature(
        Buffer.from(credential.public_key, 'base64'),
        authenticatorData,
        clientDataJSON,
        Buffer.from(payload.response.signature, 'base64')
    )) {
        return res.status(401).json({ error: "Signature verification failed." });
    }

    // success!
    console.log('Login success!');

    const user = req.session.maybe_user

    req.session.user = user;
    delete req.session.maybe_user;

    // update sign_count (?)
    await db.run(`
        UPDATE credentials
        SET sign_count=?
        WHERE user_uuid=? AND credential_id = ?`
        ,
        [
            signCount,
            user.uuid,
            selectedCredential.toString('base64'),
        ]
    );

    // update last login time
    await db.run(`
        UPDATE users
        SET last_login_at=CURRENT_TIMESTAMP
        WHERE uuid = ?`
        , [user.uuid]
    );

    res.json({ success: true });
});


export default router;
