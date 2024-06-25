import { Injectable } from '@nestjs/common';
import { randomBytes, sign } from 'node:crypto';

@Injectable()
export class AppService {
  // public keys should be persisted in a db, and additionally encrypted
  private publicKeys = new Map<string, any>();
  // challenges should be stored in an in-memory store with a ttl
  private challenges = new Map<number, string>();

  generateOptions(user: any): PublicKeyCredentialCreationOptions {
    const bytes32 = randomBytes(32);
    const challenge = bytes32.toString('base64');
    this.challenges.set(user.id, challenge);

    return {
      // @ts-ignore
      challenge,
      rp: {
        id: 'localhost',
        name: 'Localhost WebAuthn Demo',
      },
      user: {
        // @ts-ignore
        id: btoa(''+user.id),
        name: user.name,
        displayName: user.name,
      },
      timeout: 60000,
      attestation: 'direct',
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -257,
        },
      ],
      // TODO: add excludeCredentials if user has already registered a key
      excludeCredentials: [],
    };
  }

  verify(request) {
    console.log(request.publicKey);

    this.publicKeys.set(request.user.id, {
      publicKey: request.publicKey,
      id: request.rawId,
    });
  }

  authenticate(user): PublicKeyCredentialRequestOptions {
    let challenge: any = randomBytes(32);
    const { publicKey } = this.publicKeys.get(user.id);
    const buf = Buffer.from(`-----BEGIN PUBLIC KEY-----${challenge}-----END PUBLIC KEY-----`);

    const signed = sign('es256', buf, publicKey);
    challenge = challenge.toString('base64');
    this.challenges.set(user.id, challenge);

    return {
      // @ts-ignore
      challenge: signed.toString('base64'),
      rpId: 'localhost',
    };
  }

  verifyAuthentication(request) {
    const publicKey = this.publicKeys.get(request.user.id);
    if (!publicKey) {
      throw new Error('User has not registered a key');
    }

    const challenge = this.challenges.get(request.user.id);
    if (challenge !== request.challenge) {
      throw new Error('Invalid challenge' + challenge + ' ' + request.challenge);
    }

    return true;
  }
}
