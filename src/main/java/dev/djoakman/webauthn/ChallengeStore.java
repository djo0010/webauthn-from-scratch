package dev.djoakman.webauthn;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

/**
 * The server's memory of "which challenge did I issue to this browser?".
 *
 * A challenge is a nonce (number used once). The security property this class
 * owns:
 * a challenge is accepted at most once, only by the session it was issued to,
 * and
 * only within {@link #TTL} of being issued. See Notes §1 "Nonces and replay
 * prevention"
 * and WebAuthn §13.4.3.
 */
@Component
public class ChallengeStore {

	/** Session attribute key under which the pending challenge is stored. */
	static final String ATTR = "webauthn.challenge";

	/** How long an issued challenge stays valid. */
	static final Duration TTL = Duration.ofMinutes(5);

	/**
	 * Length of a challenge in bytes. The spec requires at least 16; 32 is
	 * conventional.
	 */
	static final int CHALLENGE_BYTES = 32;

	private final SecureRandom random = new SecureRandom();

	/**
	 * Generate a fresh challenge, remember it against this session (with the time
	 * it was
	 * issued), and return it. Any previously pending challenge for the session is
	 * replaced.
	 *
	 * @return the raw challenge bytes (NOT base64url — encoding is the caller's
	 *         concern)
	 */
	public byte[] issue(HttpSession session) {
		// make a 32 byte array and fill it from the CSPRNG so nobody can predict it
		byte[] challengeBytes = new byte[CHALLENGE_BYTES];
		random.nextBytes(challengeBytes);

		// tie the challenge and its issue time to this session and hand the bytes back
		session.setAttribute(ATTR, new Pending(challengeBytes, Instant.now()));
		return challengeBytes;
	}

	/**
	 * Return the pending challenge for this session and remove it, so it can never
	 * be
	 * accepted a second time. Fails if there is no pending challenge or it has
	 * expired.
	 *
	 * First used in M2 (registration verify). Write it now so single-use is
	 * designed in.
	 *
	 * @throws IllegalStateException if no challenge is pending or it has expired
	 */
	public byte[] consume(HttpSession session) {
		// nothing stored means no challenge was issued or it was already used
		Object attribute = session.getAttribute(ATTR);
		if (attribute == null) {
			throw new IllegalStateException("No Challenge issued");
		}

		// remove it before checking anything else so it can never be replayed
		Pending pendingValue = (Pending) attribute;
		session.removeAttribute(ATTR);

		// reject if more than five minutes have passed since it was issued
		if (Instant.now().isAfter(pendingValue.issuedAt().plus(TTL))) {
			throw new IllegalStateException("Challenge expired");
		}

		return pendingValue.challenge();
	}

	/** What gets stored in the session: the challenge plus when it was issued. */
	record Pending(byte[] challenge, Instant issuedAt) {
	}
}
