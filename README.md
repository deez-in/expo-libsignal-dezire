# expo-libsignal-dezire

[![npm](https://img.shields.io/npm/v/expo-libsignal-dezire.svg)](https://www.npmjs.com/package/expo-libsignal-dezire)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An Expo Native Module that bridges [libsignal-dezire](https://github.com/deez-in/libsignal-dezire) — a pure Rust implementation of the Signal Protocol — into React Native. This is **not** a reimplementation; it's a thin wrapper that calls compiled Rust code through platform-native FFI (C on iOS, JNI on Android).

## Where This Fits

```
┌─────────────────────────────────────────────────────────┐
│  DeezChatz Mobile (React Native / Expo)                 │
│    │                                                    │
│    └─ ⭐ expo-libsignal-dezire (this module)            │
│         │                                               │
│         ├─ iOS: Swift → C-FFI → libsignal_dezire.a      │
│         └─ Android: Kotlin → JNI → libsignal_dezire.so  │
│              │                                          │
│              └─ libsignal-dezire (pure Rust)             │
└─────────────────────────────────────────────────────────┘
```

| Layer | What it does |
|-------|-------------|
| **TypeScript** (`src/`) | Declares the native module interface and exports typed functions |
| **Swift** (`ios/LibsignalDezireModule.swift`) | Wraps C-FFI calls via `UnsafeMutablePointer`, manages ratchet state pointers |
| **Kotlin** (`android/`) | Wraps JNI calls, manages ratchet state pointers as `Long` handles |
| **Rust** (`libsignal-dezire/`) | The actual cryptographic operations (git submodule) |

---

## How It Works

1. **Rust** is compiled to a static library (`.a` for iOS, `.so` for Android) using cross-compilation scripts in `scripts/`.
2. The Rust library exposes `extern "C"` functions (iOS) and JNI-compatible functions (Android).
3. **Swift** (iOS) and **Kotlin** (Android) wrap these native calls in an Expo Native Module.
4. **TypeScript** declares the module interface, making it callable from JavaScript as `await LibsignalDezireModule.genKeyPair()`.

All cryptographic computation happens in native Rust code — JavaScript only handles the orchestration.

---

## Installation

```bash
bun add expo-libsignal-dezire
# or
npm install expo-libsignal-dezire
```

After installing, rebuild your native project:

```bash
npx expo prebuild
```

> **Note**: This module requires a custom dev client (Expo development build). It will not work with Expo Go.

---

## API Reference

Import the module:

```typescript
import LibsignalDezireModule from "expo-libsignal-dezire";
```

### Key Generation

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `genKeyPair()` | — | `Promise<KeyPair>` | Generate a Curve25519 key pair (`{ secret: Uint8Array, public: Uint8Array }`) |
| `genSecret()` | — | `Promise<Uint8Array>` | Generate a 32-byte cryptographic random secret |
| `genPubKey(k)` | `k: Uint8Array` (private key) | `Promise<Uint8Array>` | Derive the public key from a private key |

### VXEdDSA Signatures

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `vxeddsaSign(k, M)` | `k: Uint8Array` (private key), `M: Uint8Array` (message) | `Promise<VXEdDSAOutput>` | Sign a message, returning `{ signature: Uint8Array, vrf: Uint8Array }` |
| `vxeddsaVerify(u, M, signature)` | `u: Uint8Array` (public key), `M: Uint8Array` (message), `signature: Uint8Array` | `Promise<Uint8Array \| null>` | Verify a signature. Returns VRF output on success, `null` on failure |

### X3DH Key Agreement

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `x3dhInitiator(identityPrivate, bobBundle, hasOpk)` | Identity private key, serialized bundle, whether OPK is included | `Promise<X3DHInitOutput>` | Perform initiator-side X3DH → `{ sharedSecret, ephemeralPublic }` |
| `x3dhResponder(identityPrivate, signedPreKeyPrivate, oneTimePreKeyPrivate, aliceIdentityPublic, aliceEphemeralPublic)` | Bob's keys + Alice's public keys | `Promise<X3DHResponderOutput>` | Perform responder-side X3DH → `{ sharedSecret }` |

### Double Ratchet

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `ratchetInitSender(sk, receiverPub)` | Shared secret, receiver's public key | `Promise<string>` | Initialize sender ratchet state. Returns a **state pointer** (UUID string) |
| `ratchetInitReceiver(sk, receiverPriv, receiverPub)` | Shared secret, receiver's key pair | `Promise<string>` | Initialize receiver ratchet state. Returns a state pointer |
| `ratchetEncrypt(statePtr, plaintext, ad?)` | State pointer, plaintext, optional AD | `Promise<RatchetEncryptResult \| null>` | Encrypt a message → `{ header, ciphertext }` |
| `ratchetDecrypt(statePtr, header, ciphertext, ad?)` | State pointer, header, ciphertext, optional AD | `Promise<Uint8Array \| null>` | Decrypt a message → plaintext bytes |
| `ratchetFree(statePtr)` | State pointer | `Promise<void>` | **Free the Rust heap memory** for this session |
| `ratchetSerialize(statePtr)` | State pointer | `Promise<string>` | Serialize ratchet state to JSON for persistence |
| `ratchetDeserialize(json)` | JSON string | `Promise<string>` | Restore ratchet state from JSON. Returns a new state pointer |

> **⚠️ Memory Management**: Ratchet state lives on the Rust heap. The native modules (Swift/Kotlin) store opaque pointers in a `ratchetSessions` map keyed by UUID string. You **must** call `ratchetFree()` when a session is no longer needed to prevent memory leaks.

### Types

```typescript
type KeyPair = { secret: Uint8Array; public: Uint8Array };

type VXEdDSAOutput = { signature: Uint8Array; vrf: Uint8Array };

type X3DHInitOutput = { sharedSecret: Uint8Array; ephemeralPublic: Uint8Array };

type X3DHResponderOutput = { sharedSecret: Uint8Array };

type RatchetEncryptResult = { header: Uint8Array; ciphertext: Uint8Array };
```

---

## Building From Source

The Rust library must be cross-compiled for each platform target. Two scripts in `scripts/` handle this:

### Android

```bash
bun run build:android
```

Runs `scripts/cargo-android.ts`, which cross-compiles `libsignal-dezire` for:
- `aarch64-linux-android` (ARM64)
- `armv7-linux-androideabi` (ARM32)
- `x86_64-linux-android` (x86_64 emulator)

Output: `.so` files placed in `android/build/`.

### iOS

```bash
bun run build:ios        # Device (aarch64-apple-ios)
bun run build:ios-sim    # Simulator (aarch64 + x86_64, lipo'd)
```

Runs `scripts/cargo-ios.ts`, which produces a universal `.a` static library placed in `ios/rust/`.

### All Platforms

```bash
bun run build  # Runs android + ios + ios-sim sequentially
```

---

## License

MIT — Debarka Mondal
