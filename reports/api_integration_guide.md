# CRM Mobile App Integration Guide

## Base URL
All API requests should be made to:
`http://<YOUR_SERVER_IP>:8000/api/`

## Authentication Flow
The mobile app (Commercial User) uses an OTP-based login flow.

### 1. Request OTP
Send the user's phone number to request a One-Time Password.

**Endpoint**: `POST /auth/request-otp/`
**Body**:
```json
{
  "phone_number": "0661234567"
}
```
**Response**:
```json
{
  "message": "OTP sent",
  "otp": "12345" // In production, this will not be sent back!
}
```

### 2. Login & Get Token
Send the phone number and the OTP received via SMS to get an access token.

**Endpoint**: `POST /auth/login/`
**Body**:
```json
{
  "phone_number": "0661234567",
  "otp": "12345"
}
```
**Response**:
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "role": "Commercial"
}
```

### 3. Store the Token
Save the `token` securely on the device (e.g., `SharedPreferences` on Android, `Keychain` on iOS).

## Making Authenticated Requests
For all subsequent requests, include the token in the `Authorization` header.

**Header Format**:
`Authorization: Bearer <YOUR_TOKEN>`

### Example: Get User Profile
(Note: You might need to implement a specific "me" endpoint or use the ID returned if we adjust the login response. Currently, Commercial users can view their own data if they know their ID, or we can add a `/users/me/` endpoint for convenience.)

**Request**:
```http
GET /users/<USER_UUID>/
Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000
```

## Error Handling
- **401 Unauthorized**: Token is invalid or expired. Redirect user to Login.
- **403 Forbidden**: User does not have permission (e.g., Commercial user trying to access Admin logs).
- **400 Bad Request**: Invalid input data.

## Commercial User Capabilities
As a Commercial user, you currently have access to:
1.  **Login** (Get Token)
2.  **Request OTP**
3.  **View Own Profile** (If implemented/allowed)
4.  **Create Phone Prefixes** (If business logic allows)

*Note: Access to Audit Logs and Login History is strictly forbidden for Commercial users.*
