import { API_URL, JWKS_ENDPOINT } from './constants.js';
import { createHmac } from 'node:crypto';
import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';

// Initialize the JWKS client
const client = jwksClient({
    jwksUri: JWKS_ENDPOINT,
    requestHeaders: {}, // Add any necessary headers for your JWKS endpoint
    timeout: 30000 // Timeout in ms
});

/**
 * Validates an ID token
 * @param {string} idToken - The ID token to validate
 * @param {string} clientId - The client ID
 * @param {string} nonce - The nonce used in the authorization request
 * @returns {Promise<Object>} The validated token claims
 */
export async function validateIdToken(idToken, clientId, nonce) {
    const { header } = jwt.decode(idToken, { complete: true }) || {};
    if (!header || !header.kid) throw new Error('Invalid token header');

    const key = await client.getSigningKey(header.kid);
    const publicKey = key.getPublicKey();

    // Now verify the token — this checks signature, exp, iat, aud, iss
    const payload = jwt.verify(idToken, publicKey, {
        algorithms: ['RS256'],
        audience: clientId,
        issuer: API_URL,
    });

    // Optional nonce check
    if (nonce && payload.nonce !== nonce) {
        throw new Error('Invalid nonce');
    }

    return payload;
}

/**
 * Verifies a webhook signature
 * @param {Object} payload - The webhook payload
 * @param {string} signature - The webhook signature
 * @param {string} clientSecret - The client secret
 * @returns {boolean} True if the signature is valid, false otherwise
 */
export function verifyWebhookSignature(payload, signature, clientSecret) {
    const hmac = createHmac('sha256', clientSecret);
    hmac.update(payload);
    const computedSignature = hmac.digest('hex');
    return computedSignature === signature;
}

/**
 * Validates the options object
 * @param {Object} options - The options object
 * @param {Array} fields - The fields to validate
 * @throws {Error} If any required field is missing or of the wrong type
 */
export function validateOptions(options, fields) {
    for (const field of fields) {
        if (!options[field.name] || typeof options[field.name] !== field.type) throw new Error(`${field.name} is required`);
    }
}