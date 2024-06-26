import { Injectable } from '@nestjs/common';
import { randomBytes, sign } from 'node:crypto';

@Injectable()
export class AppService {
  // public keys should be persisted in a db, and additionally encrypted
  private publicKeys = new Map<string, any>();
  // challenges should be stored in an in-memory store with a ttl
  private challenges = new Map<number, string>();
  private challengesAuth = new Map<number, string>();

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
    // @todo check attestation object also - if its actually signed with this publicKey - as client can send ANY data before
    // also please note - you send challenge with some random, and store it - but doesnt use - how we should verify that this data came back to our challange request
    console.log(request);
    console.log(this.challenges.get(request.user.id));

    // basic check not to rewrite data *or rewrite if needed but for now only once
    const tmp = this.publicKeys.get(request.user.id);
    if (tmp?.publicKey && tmp?.publicKey !== request.publicKey) {
      return {
        msg: 'already verified another key ' + request.user.id + ' = ' + tmp?.publicKey,
      };
    }
    this.publicKeys.set(request.user.id, {
      publicKey: request.publicKey,
      id: request.rawId,
    });
    return {
      msg: 'key is saved for ' + request.user.id + ' = ' + request.publicKey,
    };
  }

  authenticate(user): PublicKeyCredentialRequestOptions {
    const tmp = this.publicKeys.get(user.id);
    if (!tmp || !tmp?.publicKey) {
      return {
        // @ts-ignore
        msg: 'no public key for ' + user.id,
      };
    }
    const bytes32 = randomBytes(32);
    const challenge = bytes32.toString('base64');
    this.challengesAuth.set(user.id, challenge);


    // hehe?
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

  verifyAuthentication(request) {
    const publicKey = this.publicKeys.get(request.user.id);
    if (!publicKey) {
      throw new Error('User has not registered a key');
    }

    // its different challenges - for creation and for auth
    const challenge = this.challenges.get(request.user.id);
    if (challenge !== request.challenge) {
      throw new Error('Invalid challenge' + challenge + ' ' + request.challenge);
    }

    return true;
  }
}
