import { NativeModule, requireNativeModule } from "expo";

import type { KeyPair, VXEdDSAOutput, X3DHInitOutput, X3DHResponderOutput, RatchetEncryptResult } from "./LibsignalDezire.types";

declare class LibsignalDezireModule extends NativeModule {
  genKeyPair(): Promise<KeyPair>;
  genSecret(): Promise<Uint8Array>;
  genPubKey(k: Uint8Array): Promise<Uint8Array>;
  encodePublicKey(k: Uint8Array): Promise<Uint8Array>;
  vxeddsaSign(
    k: Uint8Array,
    M: Uint8Array,
  ): Promise<VXEdDSAOutput>;
  vxeddsaVerify(
    u: Uint8Array,
    M: Uint8Array,
    signature: Uint8Array,
  ): Promise<Uint8Array | null>;

  // X3DH
  x3dhInitiator(
    identityPrivate: Uint8Array,
    bobBundle: Uint8Array,
    hasOpk: boolean,
  ): Promise<X3DHInitOutput>;

  x3dhResponder(
    identityPrivate: Uint8Array,
    signedPreKeyPrivate: Uint8Array,
    oneTimePreKeyPrivate: Uint8Array | null,
    aliceIdentityPublic: Uint8Array,
    aliceEphemeralPublic: Uint8Array,
  ): Promise<X3DHResponderOutput>;


  // Ratchet
  ratchetInitSender(
    sk: Uint8Array,
    receiverPub: Uint8Array,
  ): Promise<string>;

  ratchetInitReceiver(
    sk: Uint8Array,
    receiverPriv: Uint8Array,
    receiverPub: Uint8Array,
  ): Promise<string>;

  ratchetEncrypt(
    statePtr: string,
    plaintext: Uint8Array,
    ad?: Uint8Array,
  ): Promise<RatchetEncryptResult | null>;

  ratchetDecrypt(
    statePtr: string,
    header: Uint8Array,
    ciphertext: Uint8Array,
    ad?: Uint8Array,
  ): Promise<Uint8Array | null>;

  ratchetFree(statePtr: string): Promise<void>;
  ratchetSerialize(statePtr: string): Promise<string>;
  ratchetDeserialize(json: string): Promise<string>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<LibsignalDezireModule>("LibsignalDezire");
