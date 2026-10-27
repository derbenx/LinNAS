/* Web Crypto Helper for Debian Server Manager */
let serverPublicKeyObj = null;

async function fetchServerPublicKey() {
    if (serverPublicKeyObj) return serverPublicKeyObj;
    try {
        const res = await fetch('/api/crypto/pubkey');
        const data = await res.json();
        const binaryDer = Uint8Array.from(atob(data.public_key), c => c.charCodeAt(0));
        serverPublicKeyObj = await window.crypto.subtle.importKey(
            "spki",
            binaryDer.buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );
        return serverPublicKeyObj;
    } catch (err) {
        console.error('Failed to fetch RSA public key:', err);
        return null;
    }
}

function getRandomNonce(length = 16) {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function encryptPayload(jsonObject) {
    try {
        const pubKey = await fetchServerPublicKey();
        if (!pubKey) return JSON.stringify(jsonObject);

        // Generate random 256-bit AES key for payload
        const aesKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt"]
        );

        // Export raw AES key
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

        // Encrypt AES key using RSA-OAEP
        const encryptedAesKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            pubKey,
            rawAesKey
        );

        // Generate AES-GCM IV (12 bytes)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Encrypt JSON content using AES-GCM
        const enc = new TextEncoder();
        const jsonBytes = enc.encode(JSON.stringify(jsonObject));
        const encryptedDataBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            jsonBytes
        );

        // Concatenate IV + Ciphertext
        const combinedData = new Uint8Array(iv.length + encryptedDataBuffer.byteLength);
        combinedData.set(iv, 0);
        combinedData.set(new Uint8Array(encryptedDataBuffer), iv.length);

        return JSON.stringify({
            encrypted_key: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))),
            encrypted_data: btoa(String.fromCharCode(...combinedData)),
            nonce: getRandomNonce(16),
            timestamp: Math.floor(Date.now() / 1000)
        });
    } catch (err) {
        console.error('Payload encryption error:', err);
        return JSON.stringify(jsonObject);
    }
}
