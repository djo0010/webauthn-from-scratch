# Plan — WebAuthn from scratch

**Goal:** implement both WebAuthn ceremonies without a library performing the ceremony, so
that the protocol is something you understand rather than something you configured.

**Why this one is first:** you shipped passkeys at J.B. Hunt. This converts experience you
already have into demonstrable depth, which is the cheapest credibility available to you.

**Estimated effort:** 2–3 weekends.

---

## Ground rules

1. **No WebAuthn library.** No `webauthn4j`, no `java-webauthn-server`, no SimpleWebAuthn.
   Those libraries *are* the thing being learned.
2. **Libraries that are fine:** a CBOR decoder (jackson-dataformat-cbor), JDK crypto
   (`java.security.Signature`), Jackson for JSON, Spring Boot for plumbing. Parsing CBOR by
   hand teaches you nothing; verifying a signature by hand teaches you everything.
3. **Verify against the raw bytes**, never against a re-serialized structure. This is a real
   vulnerability class, not a style preference.
4. **Write the verification steps in spec order**, and cite the section number in a comment
   for each. The README will reference these.

---

## Stack

| Piece | Choice | Note |
|---|---|---|
| API | Spring Boot 3, Java 21 | Also the stack you want more reps in |
| Storage | Postgres via Docker, or H2 | Not the point; keep it boring |
| Front end | One HTML file, vanilla JS | WebAuthn is a browser API — a framework adds nothing |
| Crypto | JDK `java.security` | `Signature.getInstance("SHA256withECDSA")` |
| CBOR | jackson-dataformat-cbor | Decoding only |

---

## Milestones

### M0 — Skeleton that reaches the authenticator
*Done when: the browser prompts for Touch ID and you get a credential object in the console.*

- Spring Boot project, one controller, one static HTML page.
- Serve over `https://localhost` or use `localhost` (WebAuthn permits it as a secure context).
- Call `navigator.credentials.create()` with a hardcoded challenge and dump the result.
- You are not verifying anything yet. This exists to prove the plumbing works before any
  cryptography is involved.

### M1 — Registration options, done properly
*Done when: options are generated server-side and the challenge is single-use.*

- `POST /register/options` returns `PublicKeyCredentialCreationOptions`.
- Challenge: 32 random bytes from `SecureRandom`, base64url encoded, stored server-side
  against the session with a 5-minute expiry.
- Real `user.id` generation — random opaque bytes, explicitly *not* the email.
- Set `rp.id`, `pubKeyCredParams` for ES256 and RS256, `authenticatorSelection`,
  `excludeCredentials` for already-registered credentials.
- Write down in the README why you chose each `authenticatorSelection` value.

### M2 — Parse and verify the attestation
*The densest milestone. Budget the most time here.*
*Done when: a credential is stored and a tampered attestation is rejected.*

- Decode the attestation object (CBOR) into `fmt`, `attStmt`, `authData`.
- Parse `authenticatorData` by byte offset: rpIdHash, flags, signCount, attestedCredentialData.
- Parse the COSE public key into something the JDK can use (`ECPublicKey` for ES256).
- Verify, in spec order: challenge matches, origin matches, type is `webauthn.create`,
  rpIdHash matches `SHA256(rp.id)`, UP flag set, UV flag if you required it.
- Handle `fmt: "none"` first, then add `packed` self-attestation.
- Store: credential ID, public key, sign counter, AAGUID, user handle, transports.

**Prove it works by breaking it.** Write tests that flip one byte of the challenge, change
the origin, clear the UP flag — and assert each is rejected. These tests are the most
valuable artifact in the repo.

### M3 — Authentication ceremony
*Done when: you can log in, and a replayed assertion fails.*

- `POST /login/options` — fresh challenge, `allowCredentials` from stored credentials.
- `POST /login/verify` — the core of the whole project:
  - rebuild the signed data as `authenticatorData ‖ SHA256(clientDataJSON)`
  - verify the ECDSA signature with the stored public key
  - validate challenge, origin, type is `webauthn.get`, rpIdHash, UP/UV flags
- Test: replay a previously valid assertion and assert it fails on challenge reuse.

### M4 — Sign counter and cloning detection
*Done when: the behaviour is implemented and the README explains why it's weak.*

- Compare the received counter to the stored one; if it did not increase and is non-zero,
  treat it as a possible clone.
- Handle the common real-world case where the counter is always 0.
- The README note matters more than the code: explain why this defense is largely
  ineffective for synced passkeys. Knowing the limits of a control is the senior signal.

### M5 — Usernameless login with discoverable credentials
*Done when: you log in without typing anything.*

- Register with `residentKey: "required"`.
- Authenticate with empty `allowCredentials`, and resolve the user from the returned
  `userHandle`.
- This is the flow real passkey deployments use; it's worth having built it.

### M6 — Hardening pass and the README
*Done when: the README is good enough that a security engineer would read the code.*

- Rate limit the options endpoints.
- Constant-time comparison for challenges.
- Verify that failure responses do not leak whether an account exists.
- Then write the README — see below. **Budget real time for this. It is the deliverable.**

---

## What the README must contain

For security work, the README is judged more heavily than the code. It should establish
that you understand the threat model, not just that you got the happy path working.

1. **What this is and what it deliberately is not** — "an implementation of the WebAuthn
   ceremonies for learning; not production-hardened, here is specifically what's missing."
2. **The threat model.** What attacks this stops (phishing, credential replay, database
   disclosure), and what it does not (client malware, post-auth session hijacking,
   account recovery abuse).
3. **The verification steps, mapped to spec sections.** A table: step, WebAuthn §, the
   code that implements it, the test that proves it.
4. **The byte layout of `authenticatorData`**, drawn out. It shows you parsed it rather
   than handed it to something.
5. **What you learned that surprised you.** One honest paragraph. The sign-counter
   weakness is a good candidate.
6. **The recovery problem**, stated as an open question rather than solved. Naming the
   hard problem you didn't solve reads as judgment, not as a gap.

---

## Deliberately out of scope

Say so in the README rather than leaving it ambiguous:

- Full attestation trust-chain validation against the FIDO Metadata Service
- `tpm`, `android-key`, `apple` attestation formats
- Account recovery
- Enterprise attestation
- Production key management, HSM storage, or rotation
