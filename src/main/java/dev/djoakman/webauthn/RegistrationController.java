package dev.djoakman.webauthn;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.djoakman.webauthn.RegistrationOptions.AuthenticatorSelection;
import dev.djoakman.webauthn.RegistrationOptions.PubKeyCredParam;
import dev.djoakman.webauthn.RegistrationOptions.RelyingParty;
import dev.djoakman.webauthn.RegistrationOptions.User;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Registration ceremony endpoints (WebAuthn §7.1).
 *
 * M1: /register/options — issue a challenge and describe the credential we want
 * created.
 * M2: /register/verify — parse and verify the attestation, store the
 * credential.
 */
@RestController
public class RegistrationController {

	/**
	 * Must match what the browser will see as the origin's host. For
	 * http://localhost:8080 that is "localhost".
	 */
	static final String RP_ID = "localhost";
	static final String RP_NAME = "WebAuthn from scratch";

	/**
	 * base64url without padding — the only encoding WebAuthn uses for
	 * bytes-in-JSON.
	 */
	private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

	private final ChallengeStore challenges;
	private final SecureRandom random = new SecureRandom();

	/**
	 * Spring supplies the ChallengeStore (constructor injection — no @Autowired
	 * needed with one constructor).
	 */
	public RegistrationController(ChallengeStore challenges) {
		this.challenges = challenges;
	}

	/**
	 * Step 1 of registration. Issue a fresh challenge bound to this session and
	 * return the
	 * full creation options for the browser to hand to
	 * navigator.credentials.create().
	 */
	@PostMapping("/register/options")
	public RegistrationOptions registerOptions(HttpSession session) {
		// issue a fresh challenge for this session and encode it for JSON
		byte[] challenge = challenges.issue(session);

		// encode using our encoder
		String challengeEncoded = B64URL.encodeToString(challenge);

		// the user handle is random bytes not an email so it can never leak identity
		byte[] userHandle = new byte[16];
		// fill the array
		random.nextBytes(userHandle);
		// encode using our encoder
		String userHandleEncoded = B64URL.encodeToString(userHandle);

		// the algorithms we will accept in order of preference (ES256 first then RS256)
		List<PubKeyCredParam> pubKeyCredParams = new ArrayList<>();
		pubKeyCredParams.add(new PubKeyCredParam("public-key", -7));
		pubKeyCredParams.add(new PubKeyCredParam("public-key", -257));

		// require a discoverable credential and user verification (see README for why)

		// no username needed step. the authenticator recognizes this site from its own
		// storage. (here it would see localhost)
		// offers the stored account, asks for a PIN or biometric, then signs the
		// challenge with that account's private key. the server checks the signature with the
		// public key
		AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection("required", "required");

		// assemble everything the browser needs for navigator.credentials.create()
		return new RegistrationOptions(
				challengeEncoded,
				new RelyingParty(RP_ID, RP_NAME),
				new User(userHandleEncoded, "dj_test", "DJ"),
				pubKeyCredParams,
				authenticatorSelection,
				"none",
				60_000);
	}
}
