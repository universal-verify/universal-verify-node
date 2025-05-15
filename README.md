# Universal Verify Node.js SDK

A backend SDK for integrating with Universal Verify, an OAuth/OIDC platform that enables partners to access user information securely.

## Installation

```bash
npm install universal-verify
```

## Usage

```javascript
import UniversalVerify from 'universal-verify';

// Initialize the SDK with your client credentials
const universalVerify = new UniversalVerify('your-client-id', 'your-client-secret');
```

## API Reference

### Constructor

```javascript
new UniversalVerify(clientId, clientSecret)
```

Creates a new instance of the UniversalVerify SDK.

#### Parameters

- `clientId` (string, required): Your Universal Verify client ID
- `clientSecret` (string, required): Your Universal Verify client secret

### Methods

#### createCodeChallenge(codeVerifier)

Creates a PKCE code challenge from a code verifier.

##### Parameters

- `codeVerifier` (string, optional): The code verifier. If not provided, a random one will be generated.

##### Returns

- `object`: An object containing:
  - `codeVerifier` (string): The code verifier
  - `codeChallenge` (string): The generated code challenge

#### exchangeCodeForTokens(options)

Exchanges an authorization code for access and refresh tokens.

##### Parameters

- `options` (object):
  - `code` (string, required): The authorization code provided by the authorization server
  - `codeVerifier` (string, required): The code verifier used to create the code challenge
  - `redirectUri` (string, required): The redirect URI used in the authorization request

##### Returns

- `Promise<object>`: The token response containing:
  - `access_token` (string): The access token (not provided if only the openid scope was requested)
  - `refresh_token` (string): The refresh token (not provided if only the openid scope was requested)
  - `id_token` (string): The OIDC ID token (only provided if the openid scope requested)
  - `expires_in` (number): The number of seconds until the access token expires
  - `scope` (string): Space seperated list of scopes this access_token supports
  - `sub` (string): Unique user identifier
  - `token_type` (string): The type of token (always "Bearer")

#### getUserInfo(accessToken, timezone)

Retrieves user information using an access token.

##### Parameters

- `accessToken` (string, required): The access token
- `timezone` (string, optional): The timezone to use when age is included in the response

##### Returns

- `Promise<object>`: The user information object containing:
  - `sub` (string): Unique user identifier
  - `verified` (boolean): Whether the user is verified (requires 'verification' scope)
  - `verification_confidence` (number): Confidence level of verification (1-3) (requires 'verification' scope)
  - `age` (number): User's age (requires 'age' scope)
  - `regional_info` (object): Regional information (requires one of: 'name', 'date_of_birth', or 'id_type' scopes)
    - `region` (string): User's region
    - `additional_userinfo_url` (string): URL for additional regional information

#### getRegionalUserInfo(accessToken, regionalUrl)

Retrieves user's regional information using an access token.

##### Parameters

- `accessToken` (string, required): The access token
- `regionalUrl` (string, required): The regional URL

##### Returns

- `Promise<object>`: The regional user information object containing:
  - `sub` (string): Unique user identifier
  - `name` (object): User's name information
    - `first_name` (string): User's first name
    - `middle_names` (array): Array of user's middle names
    - `last_name` (string): User's last name
    - `suffix` (string): The suffix portion of the user's name
    - `full_name` (string): User's full name with an attempt at localization
  - `date_of_birth` (string): User's date of birth in ISO 8601 format (YYYY-MM-DD)
  - `id_type` (object): Information about the ID used for verification
    - `country` (string): Country that issued the ID
    - `type` (string): Type of ID (e.g., 'state_id', 'passport')
    - `state` (string): State that issued the ID (if applicable)

#### verifyWebhookSignature(payload, signature)

Verifies a webhook signature. Throws an error if the signature is invalid.

##### Parameters

- `payload` (string, required): The webhook payload
- `signature` (string, required): The webhook signature

##### Returns

- `object`: The webhook's request body parameters containing:
  - `type` (string): The event type information (e.g. 'user.verification.updated')
  - `data` (object): The event-specific data (see webhook payload section for more details)

##### Throws

- `Error`: If the webhook signature is invalid

#### revokeToken(token)

Revokes an access or refresh token.

##### Parameters

- `token` (string, required): The token to revoke

##### Returns

- `Promise<object>`: The revocation result

#### validateIdToken(idToken, nonce)

Validates an ID token.

##### Parameters

- `idToken` (string, required): The ID token to validate
- `nonce` (string, optional): The nonce used if provided in the authorization request

##### Returns

- `Promise<object>`: The validated token claims
  - `iss` (string): The issuer (https://api.universalverify.com)
  - `sub` (string): An ID for the user unique to the integration
  - `aud` (string): Your integration's access key
  - `exp` (number): The token's expiration time (unix time)
  - `iat` (number): The issued at time (unix time)
  - `verified` (boolean): Whether the user is verified (requires 'verification' scope)
  - `verification_confidence` (number): Verification confidence level (1-3) (requires 'verification' scope)

#### refreshToken(refreshToken)

Refreshes an access token using a refresh token.

##### Parameters

- `refreshToken` (string, required): The refresh token

##### Returns

- `Promise<object>`: The new token response containing:
  - `access_token` (string): The new access token
  - `refresh_token` (string): The new refresh token
  - `expires_in` (number): The number of seconds until the access token expires
  - `scope` (string): Space seperated list of scopes this access_token supports
  - `sub` (string): Unique user identifier
  - `token_type` (string): The type of token (always "Bearer")

### Static Properties

#### version

Returns the version of the UniversalVerify library.

```javascript
console.log(UniversalVerify.version); // '0.0.1'
```

## Security Considerations

- Always use PKCE (Proof Key for Code Exchange) for secure OAuth flows
- Store client secrets securely and never expose them in client-side code
- Implement proper token validation and verification
- Use HTTPS for all communications
- Handle tokens securely and implement proper token refresh mechanisms

## Webhook Payloads

### user.verification.updated

This webhook is triggered when a user's verification status or confidence level changes.

#### Payload Structure

- `type` (string): The event type (always "user.verification.updated")
- `data` (object): The event data containing:
  - `sub` (string): Unique user identifier
  - `verified` (boolean): New verification status
  - `verification_confidence` (number | null): New verification confidence level (1-3)
  - `previous_values` (object): Previous verification values
    - `verified` (boolean): Previous verification status
    - `verification_confidence` (number | null): Previous verification confidence level

## License

MIT License - see [LICENSE](LICENSE) for details
