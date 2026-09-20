package expo.modules.libsignaldezire

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.nio.ByteBuffer
import java.nio.ByteOrder

class LibsignalDezireModule : Module() {
  // Registry to hold raw pointers (Long) to RatchetState
  private val ratchetSessions = mutableMapOf<String, Long>()
  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a
    // string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for
    // clarity.
    // The module will be accessible from `requireNativeModule('LibsignalDezire')` in JavaScript.
    Name("LibsignalDezire")

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.

    AsyncFunction("genKeyPair") { genKeyPair() ?: throw Exception("Failed to generate key pair") }

    AsyncFunction("genPubKey") { k: ByteArray ->
      genPubKey(k) ?: throw Exception("Failed to generate public key")
    }

    AsyncFunction("encodePublicKey") { k: ByteArray ->
      encodePublicKey(k) ?: throw Exception("Failed to encode public key")
    }

    AsyncFunction("genSecret") { genSecret() }

    AsyncFunction("vxeddsaSign") { k: ByteArray, m: ByteArray ->
      if (k.size != 32) {
        throw Exception("Key must be 32 bytes")
      }
      vxeddsaSign(k, m) ?: throw Exception("Signing failed")
    }

    AsyncFunction("vxeddsaVerify") { u: ByteArray, m: ByteArray, signature: ByteArray ->
      if (u.size != 33 || signature.size != 96) {
        throw Exception("Invalid input lengths")
      }
      vxeddsaVerify(u, m, signature)
    }

    // Bundle format: [identityKey:33][spkId:4][spkPublic:33][signature:96][opkId:4][opkPublic:33?]
    AsyncFunction("x3dhInitiator") {
            identityPrivate: ByteArray,
            bobBundle: ByteArray,
            hasOpk: Boolean ->
      val expectedSize = if (hasOpk) 203 else 170
      if (bobBundle.size != expectedSize) {
        throw Exception("Invalid bundle size. Expected $expectedSize, got ${bobBundle.size}")
      }
      if (identityPrivate.size != 32) {
        throw Exception("Identity private key must be 32 bytes")
      }

      // Parse bundle using ByteBuffer for little-endian integers
      val buffer = ByteBuffer.wrap(bobBundle).order(ByteOrder.LITTLE_ENDIAN)

      val bobIdentityPublic = ByteArray(33)
      buffer.get(bobIdentityPublic)

      val bobSpkId = buffer.getInt()

      val bobSpkPublic = ByteArray(33)
      buffer.get(bobSpkPublic)

      val bobSpkSignature = ByteArray(96)
      buffer.get(bobSpkSignature)

      val bobOpkId = buffer.getInt()

      val bobOpkPublic: ByteArray? =
              if (hasOpk) {
                val opk = ByteArray(33)
                buffer.get(opk)
                opk
              } else {
                null
              }

      // Call the original JNI function with individual arguments
      x3dhInitiator(
              identityPrivate,
              bobIdentityPublic,
              bobSpkId,
              bobSpkPublic,
              bobSpkSignature,
              bobOpkId,
              bobOpkPublic
      )
              ?: throw Exception("x3dhInitiator failed")
    }

    // X3DH Responder (Bob)
    AsyncFunction("x3dhResponder") {
            identityPrivate: ByteArray,
            signedPrekeyPrivate: ByteArray,
            oneTimePrekeyPrivate: ByteArray?,
            aliceIdentityPublic: ByteArray,
            aliceEphemeralPublic: ByteArray ->
      if (identityPrivate.size != 32 ||
                      signedPrekeyPrivate.size != 32 ||
                      aliceIdentityPublic.size != 33 ||
                      aliceEphemeralPublic.size != 33
      ) {
        throw Exception("Invalid input lengths")
      }
      if (oneTimePrekeyPrivate != null && oneTimePrekeyPrivate.size != 32) {
        throw Exception("One-time prekey must be 32 bytes when provided")
      }

      val sharedSecret =
              x3dhResponder(
                      identityPrivate,
                      signedPrekeyPrivate,
                      oneTimePrekeyPrivate,
                      aliceIdentityPublic,
                      aliceEphemeralPublic
              )
                      ?: throw Exception("x3dhResponder failed")

      mapOf("sharedSecret" to sharedSecret)
    }

    // ============================================================================
    // Ratchet Logic (In-Memory Only)
    // ============================================================================

    AsyncFunction("ratchetInitSender") { sharedSecret: ByteArray, receiverPublicKey: ByteArray ->
      if (sharedSecret.size != 32 || receiverPublicKey.size != 33) {
        throw Exception("Keys must be 32 bytes")
      }
      val statePtr = ratchetInitSender(sharedSecret, receiverPublicKey)
      val uuid = java.util.UUID.randomUUID().toString()
      ratchetSessions[uuid] = statePtr
      uuid
    }

    AsyncFunction("ratchetInitReceiver") {
            sharedSecret: ByteArray,
            receiverPrivateKey: ByteArray,
            receiverPublicKey: ByteArray ->
      if (sharedSecret.size != 32 || receiverPrivateKey.size != 32 || receiverPublicKey.size != 33
      ) {
        throw Exception("Keys must be 32 bytes")
      }
      val statePtr = ratchetInitReceiver(sharedSecret, receiverPrivateKey, receiverPublicKey)
      val uuid = java.util.UUID.randomUUID().toString()
      ratchetSessions[uuid] = statePtr
      uuid
    }

    AsyncFunction("ratchetEncrypt") { uuid: String, plaintext: ByteArray, ad: ByteArray? ->
      val statePtr = ratchetSessions[uuid] ?: throw Exception("Session not found")
      val adBytes = ad ?: ByteArray(0)

      val result =
              ratchetEncrypt(statePtr, plaintext, adBytes)
                      ?: throw Exception("Ratchet encrypt failed")
      result
    }

    AsyncFunction("ratchetDecrypt") {
            uuid: String,
            header: ByteArray,
            ciphertext: ByteArray,
            ad: ByteArray? ->
      val statePtr = ratchetSessions[uuid] ?: throw Exception("Session not found")
      val adBytes = ad ?: ByteArray(0)

      val result =
              ratchetDecrypt(statePtr, header, ciphertext, adBytes)
                      ?: throw Exception("Ratchet decrypt failed")
      result
    }

    AsyncFunction("ratchetSerialize") { uuid: String ->
      val statePtr = ratchetSessions[uuid] ?: throw Exception("Session not found")
      ratchetSerialize(statePtr)
    }

    AsyncFunction("ratchetDeserialize") { json: String ->
      val statePtr = ratchetDeserialize(json)
      if (statePtr == 0L) {
        throw Exception("Failed to deserialize ratchet state")
      }
      val uuid = java.util.UUID.randomUUID().toString()
      ratchetSessions[uuid] = statePtr
      uuid
    }

    AsyncFunction("ratchetFree") { uuid: String ->
      val statePtr = ratchetSessions[uuid]
      if (statePtr != null) {
        ratchetFree(statePtr)
        ratchetSessions.remove(uuid)
      }
    }
  }

  companion object {
    init {
      System.loadLibrary("libsignal_dezire")
    }

    @JvmStatic external fun genKeyPair(): Map<String, Any>?

    @JvmStatic external fun genPubKey(k: ByteArray): ByteArray?

    @JvmStatic external fun encodePublicKey(key: ByteArray): ByteArray?

    @JvmStatic external fun genSecret(): ByteArray?

    @JvmStatic external fun vxeddsaSign(k: ByteArray, m: ByteArray): Map<String, Any>?

    @JvmStatic
    external fun vxeddsaVerify(u: ByteArray, m: ByteArray, signature: ByteArray): ByteArray?

    @JvmStatic
    external fun x3dhInitiator(
            identityPrivate: ByteArray,
            bobIdentityPublic: ByteArray,
            bobSpkId: Int,
            bobSpkPublic: ByteArray,
            bobSpkSignature: ByteArray,
            bobOpkId: Int,
            bobOpkPublic: ByteArray?
    ): Map<String, Any>?

    @JvmStatic
    external fun x3dhResponder(
            identityPrivate: ByteArray,
            signedPrekeyPrivate: ByteArray,
            oneTimePrekeyPrivate: ByteArray?,
            aliceIdentityPublic: ByteArray,
            aliceEphemeralPublic: ByteArray
    ): ByteArray?

    // Ratchet JNI Declarations
    @JvmStatic external fun ratchetInitSender(sk: ByteArray, receiverData: ByteArray): Long

    @JvmStatic
    external fun ratchetInitReceiver(
            sk: ByteArray,
            receiverDhPrivate: ByteArray,
            receiverDhPublic: ByteArray
    ): Long

    @JvmStatic
    external fun ratchetEncrypt(
            statePtr: Long,
            plaintext: ByteArray,
            ad: ByteArray
    ): Map<String, Any>?

    @JvmStatic
    external fun ratchetDecrypt(
            statePtr: Long,
            header: ByteArray,
            ciphertext: ByteArray,
            ad: ByteArray
    ): ByteArray?

    @JvmStatic external fun ratchetFree(statePtr: Long)

    @JvmStatic external fun ratchetSerialize(statePtr: Long): String

    @JvmStatic external fun ratchetDeserialize(json: String): Long
  }
}
