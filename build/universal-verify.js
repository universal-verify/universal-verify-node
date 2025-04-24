import { createHmac } from 'crypto';
import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';

const API_URL = 'https://api.universalverify.com';
const JWKS_ENDPOINT = 'https://api.universalverify.com/.well-known/jwks.json';

class ApiClient {
    constructor() {}

    async exchangeCodeForTokens(params) {
        const response = await fetch(API_URL + '/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(params),
        });

        if (!response.ok) {
            throw new Error(`Token exchange failed: ${response.statusText}`);
        }

        return response.json();
    }

    async getUserInfo(accessToken, timezone) {
        let url = API_URL + '/userinfo';
        if (timezone) url += `?timezone=${timezone}`;
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get user info: ${response.statusText}`);
        }

        return response.json();
    }

    async getRegionalUserInfo(accessToken, regionalUrl) {
        const response = await fetch(regionalUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get regional user info: ${response.statusText}`);
        }

        return response.json();
    }

    async revokeToken(token, client_id, client_secret) {
        const response = await fetch(API_URL + '/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token,
                client_id,
                client_secret
            })
        });

        if (!response.ok) {
            throw new Error(`Token revocation failed: ${response.statusText}`);
        }

        return response.json();
    }

    async refreshToken(params) {
        const response = await fetch(API_URL + '/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        });

        if (!response.ok) {
            throw new Error(`Token refresh failed: ${response.statusText}`);
        }

        return response.json();
    }
}

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
async function validateIdToken(idToken, clientId, nonce) {
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
function verifyWebhookSignature(payload, signature, clientSecret) {
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
function validateOptions(options, fields) {
    for (const field of fields) {
        if (!options[field.name] || typeof options[field.name] !== field.type) throw new Error(`${field.name} is required`);
    }
}

class UniversalVerify {
    constructor(clientId, clientSecret) {
        if (!clientId || typeof clientId !== 'string') throw new Error('clientId is required');
        if (!clientSecret || typeof clientSecret !== 'string') throw new Error('clientSecret is required');
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.api = new ApiClient(clientId, clientSecret);
    }

    /**
     * Creates a code challenge
     * @param {string} codeVerifier - The code verifier
     * @returns {Object} The code challenge and verifier
     */
    createCodeChallenge(codeVerifier) {
        if (!codeVerifier) codeVerifier = crypto.randomBytes(32).toString('base64url');
        const codeChallenge = crypto
            .createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
        return { codeVerifier, codeChallenge };
    }

    /**
     * Exchanges an authorization code for access and refresh tokens
     * @param {Object} options - The options
     * @param {string} options.code - The authorization code provided by the authorization server
     * @param {string} options.codeVerifier - The code verifier used to create the code challenge
     * @param {string} options.redirectUri - The redirect URI used in the authorization request
     * @returns {Promise<Object>} The token response
     */
    async exchangeCodeForTokens(options) {
        validateOptions(options, [
            { name: 'code', type: 'string' },
            { name: 'codeVerifier', type: 'string' },
            { name: 'redirectUri', type: 'string' }
        ]);
        return await this.api.exchangeCodeForTokens({
            client_id: this.clientId,
            client_secret: this.clientSecret,
            grant_type: 'authorization_code',
            code: options.code,
            code_verifier: options.codeVerifier,
            redirect_uri: options.redirectUri,
        });
    }

    /**
     * Gets user information using an access token
     * @param {string} accessToken - The access token
     * @param {string} timezone - The timezone to when age is included in the response
     * @returns {Promise<Object>} The user information
     */
    async getUserInfo(accessToken, timezone) {
        return await this.api.getUserInfo(accessToken, timezone);
    }

    /**
     * Gets user's regional information using an access token
     * @param {string} accessToken - The access token
     * @param {string} regionalUrl - The regional URL
     * @returns {Promise<Object>} The regional user information
     */
    async getRegionalUserInfo(accessToken, regionalUrl) {
        return await this.api.getRegionalUserInfo(accessToken, regionalUrl);
    }

    /**
     * Verifies a webhook signature and returns the parsed payload
     * @param {string} payload - The webhook payload
     * @param {string} signature - The webhook signature
     * @returns {Promise<Object>} The verification result
     */
    verifyWebhookSignature(payload, signature, webhookSecret) {
        let valid = verifyWebhookSignature(payload, signature, webhookSecret);
        if (!valid) throw new Error('Invalid webhook signature');
        return JSON.parse(payload);
    }

    /**
     * Revokes an access or refresh token
     * @param {string} token - The token to revoke
     * @returns {Promise<Object>} The revocation result
     */
    async revokeToken(token) {
        return await this.api.revokeToken(token, this.clientId, this.clientSecret);
    }

    /**
     * Validates an ID token
     * @param {string} idToken - The ID token to validate
     * @param {string} nonce - The nonce used in the authorization request
     * @returns {Promise<Object>} The validated token claims
     */
    async validateIdToken(idToken, nonce) {
        return validateIdToken(idToken, this.clientId, nonce);
    }

    /**
     * Refreshes an access token using a refresh token
     * @param {string} refreshToken - The refresh token
     * @returns {Promise<Object>} The new token response
     */
    async refreshToken(refreshToken) {
        return await this.api.refreshToken({
            refresh_token: refreshToken,
            client_id: this.clientId,
            client_secret: this.clientSecret,
            grant_type: 'refresh_token',
        });
    }

    /**
     * Returns the version of the UniversalVerify library
     * @returns {string} The version of the UniversalVerify library
     */
    static get version() { return '0.0.1'; }
}

export { UniversalVerify as default };
