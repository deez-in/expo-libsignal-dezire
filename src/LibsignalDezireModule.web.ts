import { registerWebModule, NativeModule } from "expo";

import type { KeyPair, VXEdDSAOutput } from "./LibsignalDezire.types";

class LibsignalDezireModule extends NativeModule {
  async vxeddsaSign(
    _u: Uint8Array,
    _M: Uint8Array,
    _z: Uint8Array,
  ): Promise<VXEdDSAOutput> {
    throw new Error("LibsignalDezire is not available on web");
  }
  async vxeddsaVerify(
    _u: Uint8Array,
    _M: Uint8Array,
    _signature: Uint8Array,
  ): Promise<Uint8Array | null> {
    throw new Error("LibsignalDezire is not available on web");
  }
  async genPubKey(_k: Uint8Array): Promise<Uint8Array> {
    throw new Error("LibsignalDezire is not available on web");
  }
  async encodePublicKey(_k: Uint8Array): Promise<Uint8Array> {
    throw new Error("LibsignalDezire is not available on web");
  }
  async genSecret(): Promise<Uint8Array> {
    throw new Error("LibsignalDezire is not available on web");
  }
  async genKeyPair(): Promise<KeyPair> {
    throw new Error("LibsignalDezire is not available on web");
  }
}

export default registerWebModule(
  LibsignalDezireModule,
  "LibsignalDezireModule",
);
