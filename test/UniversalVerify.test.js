import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert';
import UniversalVerify from '../scripts/UniversalVerify.js';
import crypto from 'node:crypto';

const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const WEBHOOK_SECRET = 'test-webhook-secret';

describe('UniversalVerify', () => {
    let universalVerify;

    beforeEach(() => {
        universalVerify = new UniversalVerify(CLIENT_ID, CLIENT_SECRET);
    });

    test('constructor throws error if clientId is not provided', () => {
        assert.throws(() => new UniversalVerify(), {
            message: 'clientId is required'
        });
    });

    test('constructor throws error if clientId is not a string', () => {
        assert.throws(() => new UniversalVerify(123), {
            message: 'clientId is required'
        });
    });

    test('constructor throws error if clientSecret is not provided', () => {
        assert.throws(() => new UniversalVerify(CLIENT_ID), {
            message: 'clientSecret is required'
        });
    });

    test('constructor throws error if clientSecret is not a string', () => {
        assert.throws(() => new UniversalVerify(CLIENT_ID, 123), {
            message: 'clientSecret is required'
        });
    });
    
    test('constructor initializes with valid clientId and clientSecret', () => {
        const universalVerify = new UniversalVerify(CLIENT_ID, CLIENT_SECRET);
        assert.strictEqual(universalVerify.clientId, CLIENT_ID);
        assert.strictEqual(universalVerify.clientSecret, CLIENT_SECRET);
    });

    test('version returns correct version', () => {
        assert.strictEqual(UniversalVerify.version, '0.0.1');
    });

    describe('createCodeChallenge', () => {
        test('generates code challenge and verifier when no verifier provided', () => {
            const result = universalVerify.createCodeChallenge();
            
            assert.ok(result.codeVerifier);
            assert.ok(result.codeChallenge);
            assert.strictEqual(typeof result.codeVerifier, 'string');
            assert.strictEqual(typeof result.codeChallenge, 'string');
        });

        test('generates code challenge from provided verifier', () => {
            const verifier = 'test-verifier';
            const result = universalVerify.createCodeChallenge(verifier);
            
            assert.strictEqual(result.codeVerifier, verifier);
            assert.ok(result.codeChallenge);
            assert.strictEqual(typeof result.codeChallenge, 'string');
        });
    });

    describe('verifyWebhookSignature', () => {
        test('throws error for invalid signature', () => {
            const payload = JSON.stringify({ type: 'test', data: {} });
            const invalidSignature = 'invalid-signature';
            
            assert.throws(() => {
                universalVerify.verifyWebhookSignature(payload, invalidSignature, WEBHOOK_SECRET);
            }, {
                message: 'Invalid webhook signature'
            });
        });

        test('returns parsed payload for valid signature', () => {
            const payload = JSON.stringify({ type: 'test', data: {} });
            const validSignature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
            
            const result = universalVerify.verifyWebhookSignature(payload, validSignature, WEBHOOK_SECRET);
            assert.deepStrictEqual(result, JSON.parse(payload));
        });
    });
}); 