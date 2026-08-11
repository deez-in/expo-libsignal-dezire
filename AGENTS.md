# AGENTS.md — expo-libsignal-dezire

This document provides instructions and context for AI coding agents working in this repository.

## Ecosystem Context

> **This module wraps `libsignal-dezire` (Rust) for React Native / Expo.** It provides native C-FFI (iOS) and JNI (Android) bindings so `deezchatz-mobile` can perform E2EE cryptography at native speeds.

```
deezchatz-mobile  →  ⭐ expo-libsignal-dezire (this module)  →  libsignal-dezire (Rust)
```

| Relationship | Details |
|-------------|---------|
| **Depends on** | `libsignal-dezire` — included as a git submodule at `libsignal-dezire/` |
| **Used by** | `deezchatz-mobile` — the DeezChatz messaging app |
| **Coordinates with** | `deezchatz-api` uses the same `libsignal-dezire` crate server-side for signature verification |
| **Wraps** | `libsignal-dezire` (Rust crate) via git submodule or local path |

### Cross-Repo Impact Rules

- **If `libsignal-dezire` changes an FFI function signature**: you MUST update the Swift wrapper (`ios/LibsignalDezireModule.swift`), the Kotlin wrapper (`android/`), and the TypeScript declarations (`src/LibsignalDezireModule.ts`).
- **If you add a new Rust function**: it needs to be exposed in the Rust `ffi` module, then wrapped in Swift, Kotlin, and TypeScript.
- **If you change the TypeScript API**: `deezchatz-mobile`'s crypto utils will need updating.

---

## Commands

```bash
# Build everything (Android + iOS + iOS Simulator)
bun run build

# Platform-specific builds
bun run build:android          # Cross-compile Rust for Android targets
bun run build:ios              # Cross-compile Rust for iOS device
bun run build:ios-sim          # Cross-compile Rust for iOS simulator

# TypeScript
bun run prepare                # Compile TypeScript + prepare for publish
bun run clean                  # Clean build artifacts

# Expo module tools
bun run lint                   # Lint
bun run test                   # Run tests (if available)
```

---

## Project Structure

```
src/
  LibsignalDezireModule.ts     # TypeScript native module declaration (all method signatures)
  LibsignalDezire.types.ts     # TypeScript types (KeyPair, VXEdDSAOutput, etc.)
  LibsignalDezireModule.web.ts # Web stub (throws "not supported on web")
index.ts                       # Package entry point, re-exports module

ios/
  LibsignalDezireModule.swift  # Swift Expo Module wrapping C-FFI calls (~19KB, the main native file)
  LibsignalDezire.podspec      # CocoaPods spec (links the Rust static lib)
  rust/                        # Pre-built .a static libraries for iOS targets

android/
  build.gradle                 # Gradle config (links the Rust shared lib)
  src/                         # Kotlin JNI wrapper
  build/                       # Pre-built .so shared libraries for Android targets

libsignal-dezire/              # Git submodule — the actual Rust crate

scripts/
  cargo-android.ts             # Cross-compilation script for Android (ARM64, ARM32, x86_64)
  cargo-ios.ts                 # Cross-compilation script for iOS (device + simulator lipo)

expo-module.config.json        # Expo module registration config
```

---

## FFI Boundary Rules

The architecture has four layers, and they must stay in sync:

```
TypeScript declarations  ←→  Swift/Kotlin wrappers  ←→  Rust extern "C" / JNI  ←→  Rust core logic
```

1. **Rust** (`libsignal-dezire/src/ffi/` and `src/jni/`): Exposes `extern "C"` functions and JNI-compatible functions.
2. **Swift** (`ios/LibsignalDezireModule.swift`): Calls C functions via `UnsafeMutablePointer`. Manages ratchet state pointers in a `ratchetSessions: [String: OpaquePointer]` dictionary.
3. **Kotlin** (`android/src/`): Calls JNI functions. Stores ratchet state pointers as `Long` values in a `HashMap`.
4. **TypeScript** (`src/LibsignalDezireModule.ts`): Declares the `NativeModule` interface that JavaScript code calls.

**Any change to the Rust FFI surface must be reflected through all four layers.**

---

## Memory Management — CRITICAL

Ratchet state lives on the **Rust heap**, not in JavaScript's garbage-collected memory.

- Native modules store opaque pointers to Rust `RatchetState` in a map keyed by UUID string.
- `ratchetInitSender` / `ratchetInitReceiver` allocate Rust memory and return a UUID handle.
- `ratchetFree(statePtr)` deallocates the Rust memory.
- **If `ratchetFree` is not called, the memory leaks.** There is no finalizer or garbage collection for native heap memory.
- In `deezchatz-mobile`, the `RatchetSession` TypeScript class calls `ratchetFree` in its `close()` method. Always ensure `close()` is called when a session ends.

---

## Build Pipeline

### Android (`scripts/cargo-android.ts`)

Cross-compiles `libsignal-dezire` with `cargo` for three Android targets:
- `aarch64-linux-android` (ARM64 — most modern devices)
- `armv7-linux-androideabi` (ARM32 — older devices)
- `x86_64-linux-android` (x86_64 — emulators)

Requires: Android NDK installed and `ANDROID_NDK_HOME` set.

### iOS (`scripts/cargo-ios.ts`)

Cross-compiles for iOS targets:
- **Device**: `aarch64-apple-ios`
- **Simulator**: `aarch64-apple-ios-sim` + `x86_64-apple-ios` → lipo'd into a universal binary

Output goes to `ios/rust/`.

---

## Types Reference

```typescript
type KeyPair = { secret: Uint8Array; public: Uint8Array };
type VXEdDSAOutput = { signature: Uint8Array; vrf: Uint8Array };
type X3DHInitOutput = { sharedSecret: Uint8Array; ephemeralPublic: Uint8Array };
type X3DHResponderOutput = { sharedSecret: Uint8Array };
type RatchetEncryptResult = { header: Uint8Array; ciphertext: Uint8Array };
```

---

## Code Style

- **TypeScript**: Follow the same conventions as `deezchatz-mobile` (strict mode, explicit types, no `any`).
- **Swift**: Standard Swift conventions. The main file (`LibsignalDezireModule.swift`) is ~19KB — be careful with large changes.
- **Kotlin**: Standard Kotlin conventions for JNI code.
- All binary data is passed as `Uint8Array` in TypeScript, `Data` in Swift, `ByteArray` in Kotlin.
