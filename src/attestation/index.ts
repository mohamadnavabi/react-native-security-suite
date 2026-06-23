import { Platform } from 'react-native';
import { getNativeModule } from '../native/bridge';
import type {
  AttestationAssertion,
  AttestationResult,
} from '../types/detection';

export type { AttestationResult, AttestationAssertion };

/**
 * Device attestation lets your server cryptographically verify that a request
 * originated from an unmodified instance of your app running on a genuine device.
 *
 * iOS:  Uses Apple's App Attest service (DCAppAttestService, iOS 14+).
 *        Requires the "App Attest" capability in your Apple Developer account.
 * Android: Uses Google Play Integrity API (requires Google Play Services).
 *           Add `com.google.android.play:integrity` to your app's build.gradle.
 *
 * Typical flow:
 *   1. Server generates a random nonce (challenge).
 *   2. `DeviceAttestation.attestDevice(challenge)` returns an `AttestationResult`.
 *   3. Send the result to your server for verification.
 *   4. For subsequent requests, call `generateAssertion(keyId, requestHash)`.
 */
export const DeviceAttestation = {
  /** Returns true if the current OS version and runtime support attestation. */
  isSupported(): Promise<boolean> {
    return getNativeModule().deviceAttestationIsSupported();
  },

  /**
   * iOS: Generate and persist an App Attest key, returning its identifier.
   * Android: No-op (Play Integrity uses a nonce-only flow); resolves with an empty string.
   *
   * Store the returned `keyId` alongside the attestation object — you will
   * need it for `generateAssertion()`.
   */
  generateKey(): Promise<string> {
    return getNativeModule().deviceAttestationGenerateKey();
  },

  /**
   * iOS: Attest the generated key against the Apple attestation service.
   * Pass the SHA-256 hash of a server-provided challenge as `clientDataHash`
   * (base64-encoded, 32 bytes).
   *
   * Returns a base64-encoded CBOR attestation object to send to your server.
   */
  attestKey(keyId: string, clientDataHash: string): Promise<string> {
    if (!keyId || !clientDataHash) {
      return Promise.reject(new Error('keyId and clientDataHash are required'));
    }
    return getNativeModule().deviceAttestationAttestKey(keyId, clientDataHash);
  },

  /**
   * iOS: Generate an assertion for a specific request after a key has been attested.
   * `clientDataHash` is the SHA-256 of the request data / nonce (base64-encoded).
   */
  generateAssertion(
    keyId: string,
    clientDataHash: string
  ): Promise<AttestationAssertion> {
    if (!keyId || !clientDataHash) {
      return Promise.reject(new Error('keyId and clientDataHash are required'));
    }
    return getNativeModule()
      .deviceAttestationGenerateAssertion(keyId, clientDataHash)
      .then((assertion) => ({ assertion, keyId }));
  },

  /**
   * Android: Request a Play Integrity token. Pass a server-generated nonce
   * (base64url-encoded, 16–500 bytes). The token is sent to your server
   * for verification via the Play Integrity API.
   *
   * iOS: Not applicable — resolves with an empty string.
   */
  getPlayIntegrityToken(nonce: string): Promise<string> {
    if (Platform.OS !== 'android') {
      return Promise.resolve('');
    }
    if (!nonce) {
      return Promise.reject(new Error('nonce is required'));
    }
    return getNativeModule().deviceAttestationGetPlayIntegrityToken(nonce);
  },

  /**
   * Convenience: performs the full attestation flow for the current platform.
   * On iOS: calls `generateKey()` then `attestKey(keyId, clientDataHash)`.
   * On Android: calls `getPlayIntegrityToken(nonce)`.
   *
   * @param challengeHash - iOS: SHA-256 of server nonce (base64). Android: server nonce (base64url).
   */
  async attestDevice(challengeHash: string): Promise<AttestationResult> {
    if (Platform.OS === 'ios') {
      const keyId = await DeviceAttestation.generateKey();
      const attestation = await DeviceAttestation.attestKey(
        keyId,
        challengeHash
      );
      return { platform: 'app-attest', attestation, keyId };
    }
    const attestation =
      await DeviceAttestation.getPlayIntegrityToken(challengeHash);
    return { platform: 'play-integrity', attestation };
  },
};
