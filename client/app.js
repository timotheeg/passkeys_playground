export async function createAccount() {
    const username = document.getElementById('username').value;

    const data = await fetch('/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    }).then(res => res.json());

    getServerStatusDump();
}

export async function getServerStatusDump() {
    const data = await fetch('/status-dump').then(res => res.json());

    document.getElementById('res').innerText = JSON.stringify(data, null, 2);
}

function uuidToBinary(uuid) {
    const hex = uuid.replace(/-/g, '');
    return new Uint8Array(hex.match(/../g).map(byte => parseInt(byte, 16)));
}

function base64ToArrayBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function arrayBufferToBase64(buffer) {
    const binaryString = String.fromCharCode(...new Uint8Array(buffer)); // dodgy, but ok coz we expect short buffers
    return btoa(binaryString);
}

export async function register() {
    const username = document.getElementById('username').value;

    // Fetch registration options
    const options = await fetch('/account/register-options', {
        method: 'POST',
    }).then(res => res.json());

    getServerStatusDump();

    // Create credentials
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: base64ToArrayBuffer(options.challenge),
            rp: options.rp,
            user: {
                ...options.user,
                id: uuidToBinary(options.user.id)
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            authenticatorSelection: options.authenticatorSelection
        }
    });

    // json result...
    const credentialDTO = {
        id: credential.id,
        type: credential.type,
        user: {
            id: options.user.id
        },
        rawId: arrayBufferToBase64(credential.rawId),
        response: {
            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
        },
    };

    // Register with server
    await fetch('/account/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentialDTO)
    });

    getServerStatusDump();
}

export async function login() {
    console.log('login');
    const username = document.getElementById('username').value;

    // Fetch login options
    const options = await fetch('/account/login-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    }).then(res => res.json());

    console.log(options);
    getServerStatusDump();

    options.allowCredentials.forEach(cred => {
        cred.id = base64ToArrayBuffer(cred.id)
    });

    // Get credentials
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: base64ToArrayBuffer(options.challenge),
            allowCredentials: options.allowCredentials,
            timeout: options.timeout,
            userVerification: options.userVerification
        }
    });

    const loginDTO = {
        id: assertion.id,
        rawId: arrayBufferToBase64(assertion.rawId),
        authenticatorAttachment: assertion.authenticatorAttachment,
        response: {
            authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
            signature: arrayBufferToBase64(assertion.response.signature),
            userHandle: arrayBufferToBase64(assertion.response.userHandle),
        },
    };

    console.log(assertion);

    // Authenticate with server
    await fetch('/account/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginDTO),
    });

    getServerStatusDump();
}

const randomSuffix = Math.floor(Math.random() * 1000000);

// set up all listeners
document.getElementById('create').addEventListener('click', createAccount);
document.getElementById('register').addEventListener('click', register);
document.getElementById('login').addEventListener('click', login);
document.getElementById('status_dump').addEventListener('click', getServerStatusDump);
document.getElementById('username').value = `user${randomSuffix}`;

console.log('loaded');