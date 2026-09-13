package dev.djoakman.webauthn;

import java.util.List;

/**
 * Server-generated PublicKeyCredentialCreationOptions (WebAuthn §5.4) — what the browser
 * passes to navigator.credentials.create(). Mirrors the `options` object in index.html.
 *
 * Jackson serialises records field-by-field, so the component names below become the JSON
 * property names. They must match the WebAuthn dictionary names exactly.
 *
 * Encoding note: JSON cannot carry raw bytes. `challenge` and `user.id` are BufferSource
 * in the browser API but are sent here as base64url strings; index.html decodes them back
 * to Uint8Array before calling create(). Decide this once and never mix it up.
 */
public record RegistrationOptions(
		String challenge,                          // base64url, no padding
		RelyingParty rp,
		User user,
		List<PubKeyCredParam> pubKeyCredParams,
		AuthenticatorSelection authenticatorSelection,
		String attestation,                        // "none" — see Notes §3 on conveyance
		long timeout                               // milliseconds
) {

	/** §5.4.2 — who the credential is scoped to. `id` must be a registrable suffix of the origin's host. */
	public record RelyingParty(String id, String name) {
	}

	/** §5.4.3 — `id` is the user handle: opaque random bytes as base64url. NEVER an email. See §14.6.1. */
	public record User(String id, String name, String displayName) {
	}

	/** §5.3 — one accepted algorithm. `type` is always "public-key"; `alg` is a COSE identifier (-7 = ES256, -257 = RS256). */
	public record PubKeyCredParam(String type, int alg) {
	}

	/** §5.4.4 — what kind of authenticator, and whether user verification is required. Write down in the README why you chose each value. */
	public record AuthenticatorSelection(String residentKey, String userVerification) {
	}
}
