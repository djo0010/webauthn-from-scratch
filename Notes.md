# Notes — WebAuthn from scratch

Concepts to understand before and during the build. The goal is not to skim these; it's to
reach the point where you could explain each one to someone else without notes.

Check them off as they stop being things you look up.

---

## 1. Cryptographic groundwork

You do not need to implement crypto. You need to know exactly what the primitives guarantee,
because every security property of WebAuthn rests on one of them.

- [ ] **Public-key cryptography** — key pairs, and why the private key never leaves the authenticator. This single property is why a WebAuthn breach of your database leaks nothing usable.
- [ ] **Digital signatures vs encryption** — commonly conflated. WebAuthn only signs; it never encrypts.
- [ ] **ECDSA over P-256 (ES256)** — the algorithm ~99% of authenticators use. Know that it's elliptic curve, know the signature is `(r, s)`, and know it is DER-encoded in the assertion.
- [ ] **RS256 and EdDSA** — the two other algorithms you'll declare support for. Know when they appear.
- [ ] **SHA-256** — where it's used: hashing the client data, hashing the RP ID.
- [ ] **Nonces and replay prevention** — a challenge is a nonce. Understand what breaks if you reuse one, don't expire one, or don't bind one to a session.
- [ ] **Constant-time comparison** — why `Arrays.equals` on a signature or challenge is a (minor, but real) timing leak.

## 2. The WebAuthn model

- [ ] **The four parties** — Relying Party (your server), Client (the browser), Authenticator (Touch ID, YubiKey, phone), User. Most confusion comes from mixing up which one does what.
- [ ] **WebAuthn vs CTAP2** — WebAuthn is the browser-to-server API; CTAP2 is the browser-to-authenticator protocol. You implement against WebAuthn and never see CTAP2. Know that the split exists.
- [ ] **FIDO2** — the umbrella term for WebAuthn + CTAP2 together.
- [ ] **The two ceremonies** — registration (produces an *attestation*) and authentication (produces an *assertion*). Nearly every implementation bug comes from applying one ceremony's rules to the other.
- [ ] **Passkey vs security key vs platform authenticator** — passkeys are discoverable credentials that sync; a YubiKey is typically a non-discoverable cross-platform authenticator. The spec language and the marketing language differ, and you should be able to translate between them.

## 3. Registration ceremony (attestation)

- [ ] **`PublicKeyCredentialCreationOptions`** — every field, and which ones are security-relevant versus cosmetic.
- [ ] **Challenge generation** — cryptographically random, server-side, single-use, time-bounded, bound to the session that requested it.
- [ ] **`user.id` (the user handle)** — up to 64 bytes, opaque, and **must not contain PII**. Understand why: it is stored on the authenticator and may be revealed before authentication.
- [ ] **`rp.id`** — the domain scope of the credential. Understand the "registrable domain suffix" rule, and why `app.example.com` may set it to `example.com` but not to `example.co.uk`.
- [ ] **`pubKeyCredParams`** — your algorithm preference list, in order.
- [ ] **`authenticatorSelection`** — `authenticatorAttachment`, `residentKey`, `userVerification`. Know the difference between `required`, `preferred` and `discouraged`, and that `preferred` gives you no guarantee at all.
- [ ] **`excludeCredentials`** — prevents double-registering the same authenticator. Know why it exists.
- [ ] **`attestation` conveyance** — `none` / `indirect` / `direct` / `enterprise`. Know why `none` is the correct default for almost everyone, and what you would need in place to justify `direct`.
- [ ] **The attestation object** — CBOR map of `fmt`, `attStmt`, `authData`.
- [ ] **Attestation formats** — `packed`, `tpm`, `android-key`, `android-safetynet`, `apple`, `fido-u2f`, `none`. You will implement `none` and `packed`; know what the others are for.
- [ ] **Attestation trust anchors / FIDO MDS** — how you would actually verify an attestation statement chains to a real authenticator model, and why most RPs decline to do this.

## 4. Parsing the binary structures

This is where most of the actual work is, and where the learning is densest.

- [ ] **CBOR (RFC 8949)** — the encoding the attestation object uses. Understand major types, and be able to read a CBOR hex dump by hand at least once.
- [ ] **COSE keys (RFC 9052)** — the credential public key format. Know the label numbers: `1` = kty, `3` = alg, `-1`/`-2`/`-3` for EC2 curve/x/y.
- [ ] **COSE algorithm identifiers** — `-7` = ES256, `-257` = RS256, `-8` = EdDSA. Memorize ES256.
- [ ] **`authenticatorData` layout** — 32-byte rpIdHash, 1 byte flags, 4-byte big-endian signCount, then optional attestedCredentialData and extensions. Be able to write the byte offsets from memory.
- [ ] **The flags byte** — UP (bit 0), UV (bit 2), BE (bit 3), BS (bit 4), AT (bit 6), ED (bit 7). Know what each asserts.
- [ ] **`attestedCredentialData`** — AAGUID (16 bytes), 2-byte credential ID length, credential ID, then the COSE public key.
- [ ] **`clientDataJSON`** — `type`, `challenge`, `origin`, `crossOrigin`. Parse it, but validate against the *raw bytes*, not a re-serialization.
- [ ] **base64url vs base64** — different alphabet, no padding. A recurring source of bugs.
- [ ] **Big-endian byte order** — the sign counter and length fields.

## 5. Authentication ceremony (assertion)

- [ ] **`PublicKeyCredentialRequestOptions`** — and how it differs from the creation options.
- [ ] **The signature input** — `authenticatorData ‖ SHA256(clientDataJSON)`. Know this by heart; it is the single most important line in the whole protocol.
- [ ] **Verification steps, in order** — the spec lists them numbered. Know why each exists and what attack it stops.
- [ ] **Origin validation** — the mechanism that makes passkeys phishing-resistant. Understand that the *browser* supplies the origin, not the page, which is why a phishing site cannot forge it.
- [ ] **RP ID hash validation** — the second half of the same guarantee.
- [ ] **Signature counter** — how cloned-authenticator detection works, and why it is unreliable in practice (many authenticators, including most passkeys, always report 0).
- [ ] **User presence vs user verification** — UP means someone touched it; UV means someone proved they were the user (PIN, biometric). Know which one you require and why.
- [ ] **Discoverable credentials and `userHandle`** — how usernameless login works, and where the user handle comes back.
- [ ] **Conditional UI / autofill** — how passkeys appear in the browser's autofill dropdown.

## 6. Security properties and failure modes

Being able to articulate these is most of what separates you from someone who integrated a library.

- [ ] **Why passkeys are phishing-resistant** — origin binding, enforced by the browser. Be able to walk through exactly what happens when a user is tricked into visiting `exarnple.com`.
- [ ] **Why there is no shared secret** — contrast with passwords, TOTP, and SMS OTP. Your database contains only public keys.
- [ ] **Replay resistance** — challenge freshness.
- [ ] **What WebAuthn does NOT protect against** — malware on the client, session hijacking after authentication, account recovery flows (which are almost always the weakest link), and a compromised RP.
- [ ] **The account recovery problem** — the hardest unsolved problem in passwordless. If a passkey is the only factor and the device is lost, what happens? Most real breaches of passkey systems will be recovery-flow breaches.
- [ ] **Credential enumeration and privacy** — why `excludeCredentials` and error messages can leak whether an account exists.
- [ ] **Sync vs device-bound passkeys** — the BE/BS flags. Synced passkeys traded some security assurance for enormous usability gain; know which side of that trade your system is on.

## 7. Specs worth actually reading

Not skimming — reading, with the implementation open beside them.

- **W3C WebAuthn Level 3** — §7.1 (registering) and §7.2 (authenticating) are numbered verification procedures. These two sections *are* the project.
- **RFC 8949** — CBOR. You only need the major types.
- **RFC 9052** — COSE. You only need key structures and algorithm identifiers.
- **FIDO Alliance security reference** — for the threat model language.

---

## Questions you should be able to answer cold

Use these as the exit exam. If any answer is vague, that concept isn't finished.

1. A user is phished and enters their credentials on `paypa1.com`. Walk through precisely why a passkey does not authenticate. Which party enforces it?
2. Why is the signature computed over `authenticatorData ‖ SHA256(clientDataJSON)` rather than over the client data directly?
3. What exactly is stored in your database after registration, and what does an attacker get from dumping that table?
4. Why must `user.id` not be an email address?
5. What's the difference between user presence and user verification, and when does requiring UV actually buy you something?
6. The sign counter comes back as 0 on every authentication. Is that an attack? What do you do?
7. When would you set attestation to `direct`, and what infrastructure would you need before that decision is meaningful?
8. Your RP ID is `example.com` and the user authenticates from `login.example.com`. Does that work? What about from `example.com.evil.net`?
9. A user loses their only device. Design the recovery flow. Now explain why your recovery flow is the weakest part of the system.
10. What does WebAuthn give you that TOTP does not, and what attack does TOTP stop that WebAuthn doesn't need to?
