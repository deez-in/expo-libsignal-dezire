# Changelog

All notable changes to this project will be documented in this file.

## [0.7.1] - 2026-09-20
### Added
- Added `encodePublicKey` API across TypeScript, iOS (Swift), Android (Kotlin/JNI), and web wrappers to support 33-byte public key encoding introduced in `libsignal-dezire` v0.2.0.

## [0.7.0] - 2026-09-19
### Changed
- Migrated `libsignal-dezire` from a git submodule to a published `crates.io` dependency (`v0.2.0`).
- Configured a local wrapper crate to proxy `ffi` and `jni` features, ensuring seamless integration with existing Android/iOS build scripts.
- Verified compatibility with `libsignal-dezire` v0.2.0 breaking changes (including `gen_pubkey_ffi` array length and `vxeddsa_sign` return types).
