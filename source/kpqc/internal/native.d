module kpqc.internal.native;

import kpqc.types;

private extern(C) nothrow @nogc
{
    int kpqc_aimer128f_keypair(ubyte*, ubyte*);
    int kpqc_aimer128f_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer128f_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer128s_keypair(ubyte*, ubyte*);
    int kpqc_aimer128s_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer128s_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer192f_keypair(ubyte*, ubyte*);
    int kpqc_aimer192f_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer192f_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer192s_keypair(ubyte*, ubyte*);
    int kpqc_aimer192s_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer192s_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer256f_keypair(ubyte*, ubyte*);
    int kpqc_aimer256f_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer256f_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer256s_keypair(ubyte*, ubyte*);
    int kpqc_aimer256s_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_aimer256s_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae2_keypair(ubyte*, ubyte*);
    int kpqc_haetae2_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae2_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae3_keypair(ubyte*, ubyte*);
    int kpqc_haetae3_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae3_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae5_keypair(ubyte*, ubyte*);
    int kpqc_haetae5_sign(ubyte*, ulong*, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);
    int kpqc_haetae5_verify(const(ubyte)*, size_t, const(ubyte)*, size_t,
        const(ubyte)*, size_t, const(ubyte)*);

    int kpqc_ntruplus768_keypair(ubyte*, ubyte*);
    int kpqc_ntruplus768_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_ntruplus768_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_ntruplus864_keypair(ubyte*, ubyte*);
    int kpqc_ntruplus864_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_ntruplus864_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_ntruplus1152_keypair(ubyte*, ubyte*);
    int kpqc_ntruplus1152_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_ntruplus1152_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_smaugt128_keypair(ubyte*, ubyte*);
    int kpqc_smaugt128_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_smaugt128_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_smaugt192_keypair(ubyte*, ubyte*);
    int kpqc_smaugt192_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_smaugt192_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_smaugt256_keypair(ubyte*, ubyte*);
    int kpqc_smaugt256_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_smaugt256_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
    int kpqc_timer_keypair(ubyte*, ubyte*);
    int kpqc_timer_encapsulate(ubyte*, ubyte*, const(ubyte)*);
    int kpqc_timer_decapsulate(ubyte*, const(ubyte)*, const(ubyte)*);
}

package(kpqc) int signatureKeyPair(SignatureAlgorithm algorithm,
    ubyte* publicKey, ubyte* secretKey) @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f:
        return kpqc_aimer128f_keypair(publicKey, secretKey);
    case SignatureAlgorithm.aimer128s:
        return kpqc_aimer128s_keypair(publicKey, secretKey);
    case SignatureAlgorithm.aimer192f:
        return kpqc_aimer192f_keypair(publicKey, secretKey);
    case SignatureAlgorithm.aimer192s:
        return kpqc_aimer192s_keypair(publicKey, secretKey);
    case SignatureAlgorithm.aimer256f:
        return kpqc_aimer256f_keypair(publicKey, secretKey);
    case SignatureAlgorithm.aimer256s:
        return kpqc_aimer256s_keypair(publicKey, secretKey);
    case SignatureAlgorithm.haetae2:
        return kpqc_haetae2_keypair(publicKey, secretKey);
    case SignatureAlgorithm.haetae3:
        return kpqc_haetae3_keypair(publicKey, secretKey);
    case SignatureAlgorithm.haetae5:
        return kpqc_haetae5_keypair(publicKey, secretKey);
    }
}

package(kpqc) int signatureSign(SignatureAlgorithm algorithm, ubyte* signature,
    ulong* signatureLength, const(ubyte)* message, size_t messageLength,
    const(ubyte)* context, size_t contextLength, const(ubyte)* secretKey)
    @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f:
        return kpqc_aimer128f_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.aimer128s:
        return kpqc_aimer128s_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.aimer192f:
        return kpqc_aimer192f_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.aimer192s:
        return kpqc_aimer192s_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.aimer256f:
        return kpqc_aimer256f_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.aimer256s:
        return kpqc_aimer256s_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.haetae2:
        return kpqc_haetae2_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.haetae3:
        return kpqc_haetae3_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    case SignatureAlgorithm.haetae5:
        return kpqc_haetae5_sign(signature, signatureLength, message,
            messageLength, context, contextLength, secretKey);
    }
}

package(kpqc) int signatureVerify(SignatureAlgorithm algorithm,
    const(ubyte)* signature, size_t signatureLength,
    const(ubyte)* message, size_t messageLength,
    const(ubyte)* context, size_t contextLength, const(ubyte)* publicKey)
    @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f:
        return kpqc_aimer128f_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.aimer128s:
        return kpqc_aimer128s_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.aimer192f:
        return kpqc_aimer192f_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.aimer192s:
        return kpqc_aimer192s_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.aimer256f:
        return kpqc_aimer256f_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.aimer256s:
        return kpqc_aimer256s_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.haetae2:
        return kpqc_haetae2_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.haetae3:
        return kpqc_haetae3_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    case SignatureAlgorithm.haetae5:
        return kpqc_haetae5_verify(signature, signatureLength, message,
            messageLength, context, contextLength, publicKey);
    }
}

package(kpqc) int kemKeyPair(KemAlgorithm algorithm, ubyte* publicKey,
    ubyte* secretKey) @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768:
        return kpqc_ntruplus768_keypair(publicKey, secretKey);
    case KemAlgorithm.ntruPlus864:
        return kpqc_ntruplus864_keypair(publicKey, secretKey);
    case KemAlgorithm.ntruPlus1152:
        return kpqc_ntruplus1152_keypair(publicKey, secretKey);
    case KemAlgorithm.smaugT128:
        return kpqc_smaugt128_keypair(publicKey, secretKey);
    case KemAlgorithm.smaugT192:
        return kpqc_smaugt192_keypair(publicKey, secretKey);
    case KemAlgorithm.smaugT256:
        return kpqc_smaugt256_keypair(publicKey, secretKey);
    case KemAlgorithm.timer:
        return kpqc_timer_keypair(publicKey, secretKey);
    }
}

package(kpqc) int kemEncapsulate(KemAlgorithm algorithm, ubyte* ciphertext,
    ubyte* sharedSecret, const(ubyte)* publicKey) @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768:
        return kpqc_ntruplus768_encapsulate(ciphertext, sharedSecret,
            publicKey);
    case KemAlgorithm.ntruPlus864:
        return kpqc_ntruplus864_encapsulate(ciphertext, sharedSecret,
            publicKey);
    case KemAlgorithm.ntruPlus1152:
        return kpqc_ntruplus1152_encapsulate(ciphertext, sharedSecret,
            publicKey);
    case KemAlgorithm.smaugT128:
        return kpqc_smaugt128_encapsulate(ciphertext, sharedSecret, publicKey);
    case KemAlgorithm.smaugT192:
        return kpqc_smaugt192_encapsulate(ciphertext, sharedSecret, publicKey);
    case KemAlgorithm.smaugT256:
        return kpqc_smaugt256_encapsulate(ciphertext, sharedSecret, publicKey);
    case KemAlgorithm.timer:
        return kpqc_timer_encapsulate(ciphertext, sharedSecret, publicKey);
    }
}

package(kpqc) int kemDecapsulate(KemAlgorithm algorithm, ubyte* sharedSecret,
    const(ubyte)* ciphertext, const(ubyte)* secretKey) @trusted nothrow @nogc
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768:
        return kpqc_ntruplus768_decapsulate(sharedSecret, ciphertext,
            secretKey);
    case KemAlgorithm.ntruPlus864:
        return kpqc_ntruplus864_decapsulate(sharedSecret, ciphertext,
            secretKey);
    case KemAlgorithm.ntruPlus1152:
        return kpqc_ntruplus1152_decapsulate(sharedSecret, ciphertext,
            secretKey);
    case KemAlgorithm.smaugT128:
        return kpqc_smaugt128_decapsulate(sharedSecret, ciphertext, secretKey);
    case KemAlgorithm.smaugT192:
        return kpqc_smaugt192_decapsulate(sharedSecret, ciphertext, secretKey);
    case KemAlgorithm.smaugT256:
        return kpqc_smaugt256_decapsulate(sharedSecret, ciphertext, secretKey);
    case KemAlgorithm.timer:
        return kpqc_timer_decapsulate(sharedSecret, ciphertext, secretKey);
    }
}
