module kpqc.types;

/// Supported signature parameter sets.
enum SignatureAlgorithm : ubyte
{
    aimer128f,
    aimer128s,
    aimer192f,
    aimer192s,
    aimer256f,
    aimer256s,
    haetae2,
    haetae3,
    haetae5,
}

/// Supported key encapsulation parameter sets.
enum KemAlgorithm : ubyte
{
    ntruPlus768,
    ntruPlus864,
    ntruPlus1152,
    smaugT128,
    smaugT192,
    smaugT256,
    timer,
}

/// Byte lengths for a signature parameter set.
struct SignatureSizes
{
    /// Public-key length.
    size_t publicKey;
    /// Secret-key length.
    size_t secretKey;
    /// Signature length.
    size_t signature;
}

/// Byte lengths for a key encapsulation parameter set.
struct KemSizes
{
    /// Public-key length.
    size_t publicKey;
    /// Secret-key length.
    size_t secretKey;
    /// Ciphertext length.
    size_t ciphertext;
    /// Shared-secret length.
    size_t sharedSecret;
}

/// All supported signature parameter sets.
enum SignatureAlgorithm[9] signatureAlgorithms = [
    SignatureAlgorithm.aimer128f,
    SignatureAlgorithm.aimer128s,
    SignatureAlgorithm.aimer192f,
    SignatureAlgorithm.aimer192s,
    SignatureAlgorithm.aimer256f,
    SignatureAlgorithm.aimer256s,
    SignatureAlgorithm.haetae2,
    SignatureAlgorithm.haetae3,
    SignatureAlgorithm.haetae5,
];

/// All supported key encapsulation parameter sets.
enum KemAlgorithm[7] kemAlgorithms = [
    KemAlgorithm.ntruPlus768,
    KemAlgorithm.ntruPlus864,
    KemAlgorithm.ntruPlus1152,
    KemAlgorithm.smaugT128,
    KemAlgorithm.smaugT192,
    KemAlgorithm.smaugT256,
    KemAlgorithm.timer,
];

/// Returns the byte lengths for a signature parameter set.
SignatureSizes sizes(SignatureAlgorithm algorithm) pure nothrow @safe
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f: return SignatureSizes(32, 48, 6_944);
    case SignatureAlgorithm.aimer128s: return SignatureSizes(32, 48, 4_704);
    case SignatureAlgorithm.aimer192f: return SignatureSizes(48, 72, 15_408);
    case SignatureAlgorithm.aimer192s: return SignatureSizes(48, 72, 10_320);
    case SignatureAlgorithm.aimer256f: return SignatureSizes(64, 96, 31_360);
    case SignatureAlgorithm.aimer256s: return SignatureSizes(64, 96, 20_224);
    case SignatureAlgorithm.haetae2: return SignatureSizes(992, 1_408, 1_474);
    case SignatureAlgorithm.haetae3: return SignatureSizes(1_472, 2_112, 2_349);
    case SignatureAlgorithm.haetae5: return SignatureSizes(2_080, 2_752, 2_948);
    }
}

/// Returns the byte lengths for a key encapsulation parameter set.
KemSizes sizes(KemAlgorithm algorithm) pure nothrow @safe
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768: return KemSizes(1_152, 2_336, 1_152, 32);
    case KemAlgorithm.ntruPlus864: return KemSizes(1_296, 2_624, 1_296, 32);
    case KemAlgorithm.ntruPlus1152: return KemSizes(1_728, 3_488, 1_728, 32);
    case KemAlgorithm.smaugT128: return KemSizes(672, 832, 672, 32);
    case KemAlgorithm.smaugT192: return KemSizes(1_088, 1_312, 992, 32);
    case KemAlgorithm.smaugT256: return KemSizes(1_440, 1_728, 1_376, 32);
    case KemAlgorithm.timer: return KemSizes(672, 832, 608, 32);
    }
}

package string algorithmName(SignatureAlgorithm algorithm) pure nothrow @safe
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f: return "AIMer128f";
    case SignatureAlgorithm.aimer128s: return "AIMer128s";
    case SignatureAlgorithm.aimer192f: return "AIMer192f";
    case SignatureAlgorithm.aimer192s: return "AIMer192s";
    case SignatureAlgorithm.aimer256f: return "AIMer256f";
    case SignatureAlgorithm.aimer256s: return "AIMer256s";
    case SignatureAlgorithm.haetae2: return "HAETAE2";
    case SignatureAlgorithm.haetae3: return "HAETAE3";
    case SignatureAlgorithm.haetae5: return "HAETAE5";
    }
}

package string algorithmName(KemAlgorithm algorithm) pure nothrow @safe
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768: return "NTRU+768";
    case KemAlgorithm.ntruPlus864: return "NTRU+864";
    case KemAlgorithm.ntruPlus1152: return "NTRU+1152";
    case KemAlgorithm.smaugT128: return "SMAUG-T128";
    case KemAlgorithm.smaugT192: return "SMAUG-T192";
    case KemAlgorithm.smaugT256: return "SMAUG-T256";
    case KemAlgorithm.timer: return "TiMER";
    }
}
