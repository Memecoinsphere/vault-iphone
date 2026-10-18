// Face ID / Touch ID via WebAuthn + extension PRF.
// La sortie PRF (secret de 32 octets calculé par l'enclave sécurisée après vérification biométrique)
// dérive la clé qui enveloppe la clé maître : la biométrie déchiffre réellement le coffre.
import { randomBytes, b64, unb64 } from './crypto.js';

export class PrfUnsupported extends Error { constructor() { super('PRF_UNSUPPORTED'); } }

export async function platformAuthenticatorAvailable() {
  try {
    return !!(window.PublicKeyCredential && window.isSecureContext &&
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

export async function registerPasskey() {
  const prfSalt = randomBytes(32);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: 'Coffre-fort' },
      user: { id: randomBytes(16), name: 'Coffre-fort', displayName: 'Coffre-fort (déverrouillage local)' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'required' },
      attestation: 'none', timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } }
    }
  });
  const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  if (!ext.prf || ext.prf.enabled === false) throw new PrfUnsupported();
  const credentialId = b64(new Uint8Array(cred.rawId));
  const first = ext.prf.results?.first;
  return { credentialId, prfSalt, prfOutput: first ? new Uint8Array(first) : null };
}

export async function evaluatePrf(credentialId, prfSalt) {
  const a = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: 'public-key', id: unb64(credentialId) }],
      userVerification: 'required', timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } }
    }
  });
  const first = a.getClientExtensionResults?.().prf?.results?.first;
  if (!first) throw new PrfUnsupported();
  return new Uint8Array(first);
}
