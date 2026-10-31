---
name: implementing-hardware-security-key-authentication
description: Builds a FIDO2/WebAuthn relying party server with the python-fido2 library, covering registration and authentication ceremonies, YubiKey enrollment, resident key (discoverable credential/passkey) workflows, and user verification policies.
subdomain: identity-and-access-management
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
upstream: implementing-hardware-security-key-authentication@54a7988 Apache-2.0, modified by wesh
---
Not for: without HTTPS in production (WebAuthn requires a secure origin), for systems where users cannot physically access a USB/NFC port, or as the sole authentication factor without a recovery mechanism for lost keys.

## Prerequisites

- Python 3.10+ with `fido2` (python-fido2 >= 2.0.0), `flask`, and `cryptography` libraries installed
- HTTPS-enabled web server (WebAuthn API requires secure context; localhost is exempt for development)
- FIDO2-compatible hardware security key (YubiKey 5 Series, SoloKeys, Titan Security Key) or platform authenticator
- Modern web browser supporting WebAuthn API (Chrome 67+, Firefox 60+, Safari 14+, Edge 79+)
- Understanding of public key cryptography, challenge-response protocols, and HTTP session management

## Workflow

### Step 1: Relying Party Server Configuration

Configure WebAuthn relying party (RP) identity and server:

- **Define RP identity**: Create a `PublicKeyCredentialRpEntity` with relying party name (display name shown to users) and RP ID (effective domain of application). RP ID must be registrable domain suffix of origin -- e.g., `example.com` is valid for `https://auth.example.com` but `other.com` is not.
- **Initialize Fido2Server**: Instantiate the `Fido2Server` class from python-fido2 library with RP entity. server handles challenge generation, attestation verification, and assertion validation.
- **Configure attestation preference**: Set attestation conveyance preference to control whether server requests proof of authenticator's identity:
  - `none`: No attestation requested (simplest, recommended for most deployments)
  - `indirect`: Attestation may be provided but CA may anonymize it
  - `direct`: Full attestation chain from authenticator's manufacturer
  - `enterprise`: Device-identifying attestation for managed environments
- **Session management**: Configure server-side sessions to store WebAuthn state between begin and complete phases of registration/authentication ceremonies. Use secure, httponly cookies with SameSite=Strict.
- **Credential storage**: Design database schema to store credential records: `credential_id` (binary), `public_key` (COSE key), `sign_count` (uint32 for clone detection), `user_id`, `created_at`, `last_used`, `display_name`, and `transports` (USB, NFC, BLE, internal).

### Step 2: Registration Ceremony (Credential Creation)

Implement WebAuthn registration flow to create new credentials:

- **Begin registration**: Call `server.register_begin()` with user entity (`PublicKeyCredentialUserEntity` containing user ID, username, and display name), list of existing credentials for user (to prevent duplicate registration), and options for `user_verification` and `authenticator_attachment`.
- **Authenticator selection criteria**:
  - `authenticator_attachment: cross-platform` restricts to roaming authenticators (USB/NFC keys)
  - `authenticator_attachment: platform` restricts to built-in authenticators (Touch ID, Windows Hello)
  - Omitting this field allows both types
  - `resident_key: required` forces creation of discoverable credential (passkey) stored on authenticator
  - `user_verification: required` enforces PIN or biometric verification on authenticator
- **Client-side ceremony**: browser calls `navigator.credentials.create()` with options from server. authenticator generates new key pair, stores private key in its secure element, and returns public key, credential ID, attestation object, and client data JSON.
- **Complete registration**: Call `server.register_complete()` with saved state and client response. server verifies attestation signature, extracts credential public key and ID, and returns `AuthenticatorData` containing credential data to store.
- **Store credential**: Persist the `credential_data` (contains `credential_id`, `public_key` as COSE key, and `sign_count`) to database associated with user account.

### Step 3: Authentication Ceremony (Assertion)

Implement WebAuthn authentication flow to verify credentials:

- **Begin authentication**: Call `server.authenticate_begin()` with list of registered credentials for user (or omit for discoverable credential flows where authenticator identifies user). Set `user_verification` based on assurance level required.
- **Client-side assertion**: browser calls `navigator.credentials.get()` with server options. authenticator locates matching credential, performs user verification if required, increments signature counter, and signs challenge with private key.
- **Complete authentication**: Call `server.authenticate_complete()` with saved state, registered credentials, and client response. server verifies assertion signature against stored public key and validates signature counter has incremented (clone detection).
- **Update sign count**: After successful authentication, update stored `sign_count` for credential. If new sign count is not greater than stored value, key may have been cloned -- flag this as security event.
- **Discoverable credential flow**: For passwordless authentication, user does not need to enter username first. authenticator presents all discoverable credentials for RP ID, and selected credential's `userHandle` identifies user.

### Step 4: YubiKey Enrollment and Management

Implement organizational YubiKey provisioning workflows:

- **PIN initialization**: Before first use, YubiKey requires FIDO2 PIN (minimum 4 characters, 8 retries before lockout). Guide users through PIN setup using Yubico Authenticator application or programmatically via CTAP2 `clientPin` command.
- **Primary key enrollment**: Register user's primary YubiKey with their account. Store credential with user-friendly label (e.g., "USB-A YubiKey - Office") and authenticator's AAGUID for device identification.
- **Backup key enrollment**: Require users to register at least two security keys. backup key should be stored separately (home, safety deposit box). Both keys must be registered to same account so either can authenticate.
- **Key attestation verification**: For enterprise deployments, verify attestation certificate chain to confirm key is genuine YubiKey from Yubico. Compare AAGUID against Yubico's published values to identify exact model.
- **Key lifecycle management**: Implement administrative functions to list user's registered keys, revoke compromised keys, force re-enrollment, and audit key usage patterns (last authentication time, total authentications).

### Step 5: Passkey Migration Strategy

Plan and execute migration from passwords to passkeys:

- **Phased rollout**: Begin with voluntary passkey enrollment alongside existing password authentication. Track adoption metrics (percentage of users with passkeys, percentage of logins using passkeys vs. passwords).
- **Credential upgrade flow**: When user authenticates with password, prompt them to register passkey. Present WebAuthn registration dialog immediately after successful password login to minimize friction.
- **Cross-device passkeys**: Support synced passkeys (passkeys stored in platform credential managers like iCloud Keychain, Google Password Manager, or 1Password) for users who do not have hardware security keys. These provide phishing resistance without requiring dedicated hardware.
- **Account recovery**: Design recovery flows for users who lose all their security keys:
  - Recovery codes generated at enrollment time (printed, stored in password manager)
  - Supervised re-enrollment by administrator after identity verification
  - Temporary time-limited password login with mandatory key re-enrollment
  - Never allow recovery via email or SMS alone, as these defeat phishing resistance
- **Password deprecation timeline**: After passkey adoption exceeds target threshold, enforce passkey-only authentication for high-privilege accounts first, then expand to all accounts. Maintain password as fallback during transition window.
- **Monitoring and metrics**: Track registration success rates, authentication failure rates (wrong key, timeout, cancelled), mean time to authenticate, and ratio of passkey to password logins.

## Key Concepts

| Term | Definition |
|------|------------|
| **FIDO2** | umbrella term for combination of W3C WebAuthn API and FIDO Alliance CTAP2 protocol, enabling passwordless and phishing-resistant authentication using public key cryptography |
| **WebAuthn** | W3C Web Authentication API that allows web applications to create and use public key credentials via `navigator.credentials.create()` (registration) and `navigator.credentials.get()` (authentication) |
| **CTAP2** | Client to Authenticator Protocol version 2; protocol used by browser (client) to communicate with external authenticators over USB, NFC, or BLE |
| **Relying Party (RP)** | web application or service that requests authentication; identified by its RP ID (domain) and RP name (display string) |
| **Discoverable Credential (Passkey)** | credential stored on authenticator that can be enumerated without RP providing credential ID, enabling username-less authentication flows |
| **Attestation** | Cryptographic proof from authenticator about its identity and properties; used by RP to verify authenticator model and manufacturer |
| **AAGUID** | Authenticator Attestation Globally Unique Identifier; 128-bit value identifying authenticator model (e.g., all YubiKey 5 NFC devices share same AAGUID) |
| **Sign Count** | monotonically increasing counter maintained by authenticator and included in each assertion; used by RP to detect cloned authenticators |
| **User Verification (UV)** | Local authentication on authenticator itself (PIN, fingerprint, face recognition) that proves person holding authenticator is legitimate owner |

## Tools & Systems

- **python-fido2**: Yubico's official Python library (v2.0+) providing `Fido2Server` for relying party implementation and `CtapHidDevice`/`Fido2Client` for direct authenticator communication over USB
- **YubiKey 5 Series**: Yubico hardware security keys supporting FIDO2/CTAP2, U2F, PIV, OpenPGP, and OTP; available in USB-A, USB-C, NFC, and Nano form factors
- **py_webauthn**: Duo Labs' Python WebAuthn library providing `generate_registration_options()`, `verify_registration_response()`, `generate_authentication_options()`, and `verify_authentication_response()` functions
- **Yubico Authenticator**: Desktop and mobile application for managing YubiKey FIDO2 credentials, setting PINs, and viewing registered accounts
- **WebAuthn.io / demo.yubico.com**: Online testing tools for verifying WebAuthn registration and authentication flows against real authenticators

## FIDO2 Deployment Report

**Application**: auth.example.com
**RP ID**: example.com
**Date**: 2026-03-19

### Enrollment Summary
- **Total Users**: 50
- **Users with Primary Key**: 50 (100%)
- **Users with Backup Key**: 47 (94%)
- **Authenticator Models**: YubiKey 5 NFC (48), YubiKey 5C NFC (2)

### Authentication Metrics (Last 30 Days)
- **Total Authentications**: 12,847
- **FIDO2 Authentications**: 12,203 (95.0%)
- **TOTP Fallback**: 644 (5.0%) -- grace period active
- **Mean Authentication Time**: 2.3 seconds
- **Authentication Failures**: 127 (0.99%)
  - User cancelled: 89
  - Timeout: 23
  - Invalid signature: 12
  - Sign count regression (possible clone): 3

### Security Events
- **Lost Key Reports**: 2
  - User A: primary key lost 2026-03-12, revoked, backup promoted, new backup enrolled
  - User B: backup key damaged 2026-03-15, revoked, replacement enrolled

### Credential Details
| User | Key Label | AAGUID | Registered | Last Used | Sign Count |
|------|-----------|--------|------------|-----------|------------|
| alice | YubiKey Primary | 2fc0579f... | 2026-02-15 | 2026-03-19 | 847 |
| alice | YubiKey Backup | 2fc0579f... | 2026-02-15 | 2026-03-01 | 12 |
| bob | YubiKey Primary | 2fc0579f... | 2026-02-16 | 2026-03-19 | 631 |
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-hardware-security-key-authentication
