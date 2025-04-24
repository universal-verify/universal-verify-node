import { API_URL } from './constants.js';

export class ApiClient {
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