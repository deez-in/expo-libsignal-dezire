import ExpoModulesCore

public class LibsignalDezireModule: Module {
    // Each module class must implement the definition function. The definition consists of components
    // that describes the module's functionality and behavior.
    // See https://docs.expo.dev/modules/module-api for more details about available components.
    public func definition() -> ModuleDefinition {
        // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
        // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
        // The module will be accessible from `requireNativeModule('LibsignalDezire')` in JavaScript.
        Name("LibsignalDezire")

        // Defines a JavaScript synchronous function that runs the native code on the JavaScript thread.
        AsyncFunction("vxeddsaSign") { (uData: Data, MData: Data) -> [String: Data] in
            let u = [UInt8](uData)
            let M = [UInt8](MData)

            guard u.count == 32 else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Key must be 32 bytes"])
            }
            
            let outputPtr = UnsafeMutablePointer<VXEdDSAOutput>.allocate(capacity: 1)
            defer { outputPtr.deallocate() }
            
            let result = vxeddsa_sign_ffi(u, M, M.count, outputPtr)
            
            if result != 0 {
                throw NSError(
                    domain: "LibsignalDezire", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Signing failed"])
            }

            // Access the C-tuples/arrays.
            let signature = withUnsafePointer(to: &outputPtr.pointee.signature) {
                Data(bytes: $0, count: 96)
            }
            let vrf_output = withUnsafePointer(to: &outputPtr.pointee.vrf) {
                Data(bytes: $0, count: 32)
            }

            return [
                "signature": signature,
                "vrf": vrf_output,
            ]
        }
        AsyncFunction("genPubKey") { (kData: Data) -> Data in
            let k = [UInt8](kData)
            
            guard k.count == 32 else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Key must be 32 bytes"])
            }
            
            var pubkey = [UInt8](repeating: 0, count: 33)
            gen_pubkey_ffi(k, &pubkey)
            return Data(pubkey)
        }

        AsyncFunction("encodePublicKey") { (kData: Data) -> Data in
            let k = [UInt8](kData)
            
            guard k.count == 32 else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Key must be 32 bytes"])
            }
            
            var pubkey = [UInt8](repeating: 0, count: 33)
            encode_public_key_ffi(k, &pubkey)
            return Data(pubkey)
        }

        AsyncFunction("genSecret") { () -> Data in
            var secret = [UInt8](repeating: 0, count: 32)
            gen_secret_ffi(&secret)
            return Data(secret)
        }
        AsyncFunction("genKeyPair") { () -> [String: Data] in
            var keys = gen_keypair_ffi()

            // Access the C-tuples/arrays.
            let secretData = withUnsafePointer(to: &keys.secret) {
                Data(bytes: $0, count: 32)
            }
            let publicData = withUnsafePointer(to: &keys.public_) {
                Data(bytes: $0, count: 33)
            }

            return [
                "secret": secretData,
                "public": publicData,
            ]
        }

        AsyncFunction("vxeddsaVerify") { (uData: Data, MData: Data, signatureData: Data) -> Data? in
            let u = [UInt8](uData)
            let M = [UInt8](MData)
            let signature = [UInt8](signatureData)

            guard u.count == 33, signature.count == 96 else {
                
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid input lengths"])
            }

            var v_out = [UInt8](repeating: 0, count: 32)
            let isValid = vxeddsa_verify_ffi(u, M, M.count, signature, &v_out)

            if isValid {
                return Data(v_out)
            } else {
                return nil
            }
        }

        // X3DH Initiator (Alice)
        // Bundle format: [identityKey:33][spkId:4][spkPublic:33][signature:96][opkId:4][opkPublic:33?]
        // Total: 170 bytes (without OPK) or 203 bytes (with OPK)
        AsyncFunction("x3dhInitiator") { (
            identityPrivate: Data,
            bobBundle: Data,
            hasOpk: Bool
        ) -> [String: Data] in
            // Validate bundle size
            let expectedSize = hasOpk ? 203 : 170
            guard bobBundle.count == expectedSize else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid bundle size. Expected \(expectedSize), got \(bobBundle.count)"])
            }
            
            guard identityPrivate.count == 32 else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Identity private key must be 32 bytes"])
            }
            
            // Parse bundle
            let bobIdentityPublic = [UInt8](bobBundle.subdata(in: 0..<33))
            let bobSpkId = bobBundle.subdata(in: 33..<37).withUnsafeBytes { $0.load(as: UInt32.self) }
            let bobSpkPublic = [UInt8](bobBundle.subdata(in: 37..<70))
            let bobSpkSignature = [UInt8](bobBundle.subdata(in: 70..<166))
            let bobOpkId = bobBundle.subdata(in: 166..<170).withUnsafeBytes { $0.load(as: UInt32.self) }
            let bobOpkPublic: [UInt8] = hasOpk ? [UInt8](bobBundle.subdata(in: 170..<203)) : [UInt8](repeating: 0, count: 33)
            let identityPrivateBytes = [UInt8](identityPrivate)

            let outputPtr = UnsafeMutablePointer<X3DHInitOutput>.allocate(capacity: 1)
            defer { outputPtr.deallocate() }

            // Build and call FFI using withUnsafeBytes to avoid tuple conversions
            var bundleInput = X3DHBundleInput()
            withUnsafeMutableBytes(of: &bundleInput.identity_public) { ptr in
                _ = bobIdentityPublic.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 33)
                }
            }
            bundleInput.spk_id = bobSpkId
            withUnsafeMutableBytes(of: &bundleInput.spk_public) { ptr in
                _ = bobSpkPublic.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 33)
                }
            }
            withUnsafeMutableBytes(of: &bundleInput.spk_signature) { ptr in
                _ = bobSpkSignature.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 96)
                }
            }
            bundleInput.opk_id = bobOpkId
            withUnsafeMutableBytes(of: &bundleInput.opk_public) { ptr in
                _ = bobOpkPublic.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 33)
                }
            }
            bundleInput.has_opk = hasOpk

            identityPrivateBytes.withUnsafeBytes { idPrivPtr in
                let idPriv = idPrivPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                x3dh_initiator_ffi(idPriv, &bundleInput, outputPtr)
            }

            let sharedSecret = withUnsafePointer(to: &outputPtr.pointee.shared_secret) {
                Data(bytes: $0, count: 32)
            }
            let ephemeralPublic = withUnsafePointer(to: &outputPtr.pointee.ephemeral_public) {
                Data(bytes: $0, count: 33)
            }
            let status = outputPtr.pointee.status

            if status != 0 {
                throw NSError(
                    domain: "LibsignalDezire", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: "X3DH initiator failed with status \(status)"])
            }

            return [
                "sharedSecret": sharedSecret,
                "ephemeralPublic": ephemeralPublic
            ]
        }

        // X3DH Responder (Bob)
        AsyncFunction("x3dhResponder") { (
            identityPrivate: Data,
            signedPrekeyPrivate: Data,
            oneTimePrekeyPrivate: Data?,
            aliceIdentityPublic: Data,
            aliceEphemeralPublic: Data
        ) -> [String: Data] in
            guard identityPrivate.count == 32,
                  signedPrekeyPrivate.count == 32,
                  aliceIdentityPublic.count == 33,
                  aliceEphemeralPublic.count == 33 else {
                throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid input lengths"])
            }

            let hasOpk = oneTimePrekeyPrivate != nil && oneTimePrekeyPrivate!.count == 32

            if hasOpk {
                guard let opk = oneTimePrekeyPrivate, opk.count == 32 else {
                    throw NSError(
                        domain: "LibsignalDezire", code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "One-time prekey must be 32 bytes when provided"])
                }
            }

            // Convert to byte arrays
            let identityPrivateBytes = [UInt8](identityPrivate)
            let spkPrivateBytes = [UInt8](signedPrekeyPrivate)
            let opkPrivateBytes: [UInt8] = oneTimePrekeyPrivate != nil ? [UInt8](oneTimePrekeyPrivate!) : [UInt8](repeating: 0, count: 32)
            let aliceIdPubBytes = [UInt8](aliceIdentityPublic)
            let aliceEkPubBytes = [UInt8](aliceEphemeralPublic)

            let outputPtr = UnsafeMutablePointer<X3DHResponderOutput>.allocate(capacity: 1)
            defer { outputPtr.deallocate() }

            // Build responder input using memcpy
            var responderInput = X3DHResponderInput()
            withUnsafeMutableBytes(of: &responderInput.identity_private) { ptr in
                _ = identityPrivateBytes.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 32)
                }
            }
            withUnsafeMutableBytes(of: &responderInput.spk_private) { ptr in
                _ = spkPrivateBytes.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 32)
                }
            }
            withUnsafeMutableBytes(of: &responderInput.opk_private) { ptr in
                _ = opkPrivateBytes.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 32)
                }
            }
            responderInput.has_opk = hasOpk

            // Build alice keys using memcpy
            var aliceKeys = X3DHAliceKeys()
            withUnsafeMutableBytes(of: &aliceKeys.identity_public) { ptr in
                _ = aliceIdPubBytes.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 33)
                }
            }
            withUnsafeMutableBytes(of: &aliceKeys.ephemeral_public) { ptr in
                _ = aliceEkPubBytes.withUnsafeBytes { src in
                    memcpy(ptr.baseAddress!, src.baseAddress!, 33)
                }
            }

            x3dh_responder_ffi(&responderInput, &aliceKeys, outputPtr)

            let sharedSecret = withUnsafePointer(to: &outputPtr.pointee.shared_secret) {
                Data(bytes: $0, count: 32)
            }
            let status = outputPtr.pointee.status

            if status != 0 {
                throw NSError(
                    domain: "LibsignalDezire", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: "X3DH responder failed with status \(status)"])
            }

            return [
                "sharedSecret": sharedSecret
            ]
        }


        
        // ============================================================================
        // Ratchet Logic (In-Memory Only)
        // ============================================================================
        
        // Registry to hold opaque pointers to RatchetState
        var ratchetSessions = [String: OpaquePointer]()
        
        AsyncFunction("ratchetInitSender") { (sharedSecret: Data, receiverPublicKey: Data) -> String in
            guard sharedSecret.count == 32, receiverPublicKey.count == 33 else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Keys must be 32 bytes"])
            }
            
            let sk = [UInt8](sharedSecret)
            let bobPublic = [UInt8](receiverPublicKey)
            
            guard let statePtr = ratchet_init_sender_ffi(sk, bobPublic) else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Failed to initialize sender ratchet"])
            }
            
            let uuid = UUID().uuidString
            ratchetSessions[uuid] = statePtr
            return uuid
        }
        
        AsyncFunction("ratchetInitReceiver") { (sharedSecret: Data, receiverPrivateKey: Data, receiverPublicKey: Data) -> String in
            guard sharedSecret.count == 32, receiverPrivateKey.count == 32, receiverPublicKey.count == 33 else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Keys must be 32 bytes"])
            }
            
            let sk = [UInt8](sharedSecret)
            let bobPrivate = [UInt8](receiverPrivateKey)
            let bobPublic = [UInt8](receiverPublicKey)

            guard let statePtr = ratchet_init_receiver_ffi(sk, bobPrivate, bobPublic) else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Failed to initialize receiver ratchet"])
            }
            
            let uuid = UUID().uuidString
            ratchetSessions[uuid] = statePtr
            return uuid
        }
        
        AsyncFunction("ratchetEncrypt") { (uuid: String, plaintext: Data, ad: Data?) -> [String: Data] in
            guard let statePtr = ratchetSessions[uuid] else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Session not found"])
            }
            
            let ptBytes = [UInt8](plaintext)
            let adBytes = ad != nil ? [UInt8](ad!) : [UInt8]()
            
            let outputPtr = UnsafeMutablePointer<RatchetEncryptResult>.allocate(capacity: 1)
            defer { outputPtr.deallocate() }
            
            let status = ratchet_encrypt_ffi(statePtr, ptBytes, ptBytes.count, adBytes, adBytes.count, outputPtr)
            
            if status != 0 {
                 throw NSError(
                    domain: "LibsignalDezire", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: "Ratchet encrypt failed with status \(status)"])
            }
            
            let header = withUnsafePointer(to: &outputPtr.pointee.header) { ptr -> Data in
                // header is uint8_t*, need to read length
                let len = outputPtr.pointee.header_len
                return Data(bytes: outputPtr.pointee.header, count: len)
            }
            
            let ciphertext = withUnsafePointer(to: &outputPtr.pointee.ciphertext) { ptr -> Data in
                let len = outputPtr.pointee.ciphertext_len
                return Data(bytes: outputPtr.pointee.ciphertext, count: len)
            }
            
            // Important: Free the buffers allocated by Rust
            ratchet_free_result_buffers(outputPtr.pointee.header, outputPtr.pointee.header_len, outputPtr.pointee.ciphertext, outputPtr.pointee.ciphertext_len)
            
            return [
                "header": header,
                "ciphertext": ciphertext
            ]
        }
        
        AsyncFunction("ratchetDecrypt") { (uuid: String, header: Data, ciphertext: Data, ad: Data?) -> Data in
            guard let statePtr = ratchetSessions[uuid] else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Session not found"])
            }
            
            let headerBytes = [UInt8](header)
            let ctBytes = [UInt8](ciphertext)
            let adBytes = ad != nil ? [UInt8](ad!) : [UInt8]()
            
            let outputPtr = UnsafeMutablePointer<RatchetDecryptResult>.allocate(capacity: 1)
            defer { outputPtr.deallocate() }
            
            let status = ratchet_decrypt_ffi(statePtr, headerBytes, headerBytes.count, ctBytes, ctBytes.count, adBytes, adBytes.count, outputPtr)
            
            if status != 0 {
                 throw NSError(
                    domain: "LibsignalDezire", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: "Ratchet decrypt failed with status \(status)"])
            }
            
            let plaintext = withUnsafePointer(to: &outputPtr.pointee.plaintext) { ptr -> Data in
                let len = outputPtr.pointee.plaintext_len
                return Data(bytes: outputPtr.pointee.plaintext, count: len)
            }
            
            // Free the buffer allocated by Rust. The decrypt result only has one buffer to free.
            // But wait, the API exposes `ratchet_free_byte_buffer`.
            ratchet_free_byte_buffer(outputPtr.pointee.plaintext, outputPtr.pointee.plaintext_len)
            
            return plaintext
        }
        
        AsyncFunction("ratchetSerialize") { (uuid: String) -> String in
            guard let statePtr = ratchetSessions[uuid] else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Session not found"])
            }
            
            guard let cStr = ratchet_serialize(statePtr) else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Serialization failed"])
            }
            
            let str = String(cString: cStr)
            ratchet_free_string(cStr)
            return str
        }
        
        AsyncFunction("ratchetDeserialize") { (json: String) -> String in
            guard let statePtr = ratchet_deserialize(json) else {
                 throw NSError(
                    domain: "LibsignalDezire", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Deserialization failed"])
            }
            
            let uuid = UUID().uuidString
            ratchetSessions[uuid] = statePtr
            return uuid
        }

        AsyncFunction("ratchetFree") { (uuid: String) in
            guard let statePtr = ratchetSessions[uuid] else {
                return // Already freed or not found
            }
            ratchet_free_ffi(statePtr)
            ratchetSessions.removeValue(forKey: uuid)
        }

    }
}
