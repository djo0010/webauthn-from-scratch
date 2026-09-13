# DJ's M1 notes — what I learned building the registration options endpoint

Written in my own words so I can explain it without looking anything up.

---

## The three parties

- **Relying party** — my Spring server. Issues challenges, stores public keys, verifies signatures. Never sees a private key.
- **Client** — the browser. Middleman. Takes the options JSON from my server, calls `navigator.credentials.create()`, talks to the authenticator, posts the result back. Also checks that the page's origin is allowed to claim the `rp.id`.
- **Authenticator** — the thing that holds the private key and signs. Windows Hello (the TPM chip plus the PIN/face prompt), a YubiKey, my phone over Bluetooth, or a synced password manager. Always on the user's side, never the server's.

## What a credential is

A public/private key pair created for one specific site, plus an ID so both sides can refer to it. After registration:

- my database holds `{userId, credentialId, publicKey}`
- the authenticator holds `{credentialId, privateKey, rpId}`

At login the server sends a challenge, the authenticator signs it with the private key, the server checks the signature with the public key. No secret ever travels, so there is nothing to phish and a database breach only leaks public keys, which cannot sign anything.

A passkey is a credential that is also discoverable (see `residentKey` below) and usually synced across devices. All passkeys are credentials, not all credentials are passkeys.

## The challenge is a nonce

A nonce is a number used once. `ChallengeStore` owns three guarantees:

1. **Random and unpredictable** — filled from `SecureRandom`, which is a CSPRNG. `java.util.Random` would let an attacker who saw two challenges predict the third and pre-sign it.
2. **Bound to the session** — stored as a session attribute, so a response can only be checked against the challenge issued to that same browser session.
3. **Single use and time limited** — `consume` removes the challenge from the session *before* checking expiry, so a failed or expired attempt burns it too.

### Why delete on every consume

- **Replay.** The realistic attack is not guessing a signature (ECDSA P-256 makes that impossible), it is reusing a real one that was captured. Deleting the challenge means a captured response is valid for exactly one submission, and the legitimate user already spent it.
- **Probing.** After `consume` returns, the verify endpoint does more checks (origin, RP ID hash, flags). If a failed attempt did not burn the challenge, an attacker could submit many crafted responses and learn from the different error messages. Burning it means every probe costs a fresh `issue`.
- **Cost.** A user who cancels the prompt or fat fingers their PIN has to start over with a new challenge. That is normal WebAuthn behaviour.

Without deletion, a captured signature would work again for the rest of the 5 minute TTL, as long as the attacker also had the session cookie.

## `residentKey` is a setting, not a key

There is only ever one key pair. `residentKey` answers one question: **does the authenticator keep the private key, or hand it back to the server in a form only the authenticator can unlock?**

- **Resident / discoverable** (`"required"`) — the private key is stored on the authenticator inside secure hardware, along with the `rpId` and the user handle. At login the browser says "we are at localhost" and the authenticator looks up its own storage and offers the accounts it has. No username typed. This is what makes a passkey a passkey. Cost is a storage slot per credential, and old or full security keys cannot do it.
- **Non resident / server side** (`"discouraged"`) — the authenticator encrypts the private key with a master secret baked into the device, hands the ciphertext to the server as the `credentialId`, and forgets it. At login the server has to send that blob back first, so the user has to type a username so the server knows which blob. The device stores nothing per site, so one cheap key can protect unlimited accounts. This is how the original FIDO U2F security keys worked.
- **`"preferred"`** — store it if there is room, otherwise fall back. Server has to handle both shapes at login.

Either way the private key is never usable by anyone except the authenticator that made it.

## `userVerification`

Every authenticator does **user presence** (a touch or a click, proves someone was there). **User verification** adds PIN, fingerprint or face (proves it was the enrolled person).

- `"required"` — must do it. A stolen key with no PIN is useless. Fails on authenticators that cannot.
- `"preferred"` — do it if supported. The server cannot trust it happened without checking the UV flag in the response.
- `"discouraged"` — presence only.

## Why I chose `"required"` / `"required"`

This is a passwordless app. There is no password backing up the passkey, so the authenticator has to be the thing that identifies the person (user verification required). And the login flow I want to build is "hit sign in, pick an account off the device", which only works with discoverable credentials (resident key required).

What I give up: anyone with an older or PIN less security key, or a full key, gets a failure instead of a fallback. For localhost with Windows Hello that is nobody. A real product with a diverse user base would usually go `"preferred"` on at least one and handle the fallback server side.

## The user handle

`user.id` is 16 random bytes, base64url encoded. It is **not** the email or username because it gets stored on the authenticator and can be shown before the user has proven anything. In M1 it is throwaway per request. In M2 it has to be stable per user, because with a resident credential it is what comes back at login to tell the server which account this is.

## base64url everywhere

JSON cannot carry raw bytes, so `challenge` and `user.id` go over the wire as base64url without padding. The browser has to decode them back to `Uint8Array` before calling `create()`, because WebAuthn wants BufferSource for binary fields. `new Uint8Array(someString)` does not decode anything, it gives you zeros. That was my first bug.

The done condition for M1 is that `challenge_from_server` in the page output matches `clientDataJSON.challenge`. That proves the authenticator signed over the exact challenge my `ChallengeStore` issued.

## Java things I hit

- `for (byte b : array)` copies each element into `b`, so assigning to `b` does not write back to the array. Did not matter in the end because `random.nextBytes(array)` fills the whole thing in one call.
- A record has no no arg constructor, you pass every component in.
- Casting `null` to a record type succeeds, so the null check has to come before you call anything on it, otherwise you get a `NullPointerException` instead of the `IllegalStateException` the Javadoc promises.
