import { ApiClient } from './api.js';
import { validateIdToken, validateOptions, verifyWebhookSignature } from './utils.js';
import crypto from 'node:crypto';

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
    static get version() { return '0.0.2'; }
}

export default UniversalVerify;
