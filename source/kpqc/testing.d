module kpqc.testing;

import kpqc.types;

private extern(C) nothrow @nogc
{
    void kpqc_test_aes256_ecb(ubyte*, const(ubyte)*, const(ubyte)*);

    int kpqc_aimer128f_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer128f_test_entropy_remaining();
    void kpqc_aimer128f_clear_test_entropy();
    int kpqc_aimer128s_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer128s_test_entropy_remaining();
    void kpqc_aimer128s_clear_test_entropy();
    int kpqc_aimer192f_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer192f_test_entropy_remaining();
    void kpqc_aimer192f_clear_test_entropy();
    int kpqc_aimer192s_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer192s_test_entropy_remaining();
    void kpqc_aimer192s_clear_test_entropy();
    int kpqc_aimer256f_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer256f_test_entropy_remaining();
    void kpqc_aimer256f_clear_test_entropy();
    int kpqc_aimer256s_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_aimer256s_test_entropy_remaining();
    void kpqc_aimer256s_clear_test_entropy();
    int kpqc_haetae2_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_haetae2_test_entropy_remaining();
    void kpqc_haetae2_clear_test_entropy();
    int kpqc_haetae3_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_haetae3_test_entropy_remaining();
    void kpqc_haetae3_clear_test_entropy();
    int kpqc_haetae5_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_haetae5_test_entropy_remaining();
    void kpqc_haetae5_clear_test_entropy();

    int kpqc_ntruplus768_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_ntruplus768_test_entropy_remaining();
    void kpqc_ntruplus768_clear_test_entropy();
    int kpqc_ntruplus864_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_ntruplus864_test_entropy_remaining();
    void kpqc_ntruplus864_clear_test_entropy();
    int kpqc_ntruplus1152_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_ntruplus1152_test_entropy_remaining();
    void kpqc_ntruplus1152_clear_test_entropy();
    int kpqc_smaugt128_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_smaugt128_test_entropy_remaining();
    void kpqc_smaugt128_clear_test_entropy();
    int kpqc_smaugt192_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_smaugt192_test_entropy_remaining();
    void kpqc_smaugt192_clear_test_entropy();
    int kpqc_smaugt256_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_smaugt256_test_entropy_remaining();
    void kpqc_smaugt256_clear_test_entropy();
    int kpqc_timer_set_test_entropy(const(ubyte)*, size_t);
    size_t kpqc_timer_test_entropy_remaining();
    void kpqc_timer_clear_test_entropy();
}

/// Encrypts one block with AES-256 for the test-vector CTR-DRBG.
ubyte[] aes256Ecb(const(ubyte)[] key, const(ubyte)[] input) @trusted
{
    if (key.length != 32)
        throw new Exception("AES-256 key must contain 32 bytes");
    if (input.length != 16)
        throw new Exception("AES input must contain 16 bytes");
    auto output = new ubyte[16];
    kpqc_test_aes256_ecb(output.ptr, key.ptr, input.ptr);
    return output;
}

/// Installs deterministic entropy for a signature test.
void setTestEntropy(SignatureAlgorithm algorithm,
    const(ubyte)[] input) @trusted
{
    int status;
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f: status = kpqc_aimer128f_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.aimer128s: status = kpqc_aimer128s_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.aimer192f: status = kpqc_aimer192f_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.aimer192s: status = kpqc_aimer192s_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.aimer256f: status = kpqc_aimer256f_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.aimer256s: status = kpqc_aimer256s_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.haetae2: status = kpqc_haetae2_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.haetae3: status = kpqc_haetae3_set_test_entropy(input.ptr, input.length); break;
    case SignatureAlgorithm.haetae5: status = kpqc_haetae5_set_test_entropy(input.ptr, input.length); break;
    }
    if (status != 0)
        throw new Exception("failed to install deterministic entropy");
}

/// Returns the number of unused deterministic signature-test bytes.
size_t testEntropyRemaining(SignatureAlgorithm algorithm) @trusted nothrow
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f: return kpqc_aimer128f_test_entropy_remaining();
    case SignatureAlgorithm.aimer128s: return kpqc_aimer128s_test_entropy_remaining();
    case SignatureAlgorithm.aimer192f: return kpqc_aimer192f_test_entropy_remaining();
    case SignatureAlgorithm.aimer192s: return kpqc_aimer192s_test_entropy_remaining();
    case SignatureAlgorithm.aimer256f: return kpqc_aimer256f_test_entropy_remaining();
    case SignatureAlgorithm.aimer256s: return kpqc_aimer256s_test_entropy_remaining();
    case SignatureAlgorithm.haetae2: return kpqc_haetae2_test_entropy_remaining();
    case SignatureAlgorithm.haetae3: return kpqc_haetae3_test_entropy_remaining();
    case SignatureAlgorithm.haetae5: return kpqc_haetae5_test_entropy_remaining();
    }
}

/// Removes deterministic entropy from a signature test.
void clearTestEntropy(SignatureAlgorithm algorithm) @trusted nothrow
{
    final switch (algorithm)
    {
    case SignatureAlgorithm.aimer128f: kpqc_aimer128f_clear_test_entropy(); break;
    case SignatureAlgorithm.aimer128s: kpqc_aimer128s_clear_test_entropy(); break;
    case SignatureAlgorithm.aimer192f: kpqc_aimer192f_clear_test_entropy(); break;
    case SignatureAlgorithm.aimer192s: kpqc_aimer192s_clear_test_entropy(); break;
    case SignatureAlgorithm.aimer256f: kpqc_aimer256f_clear_test_entropy(); break;
    case SignatureAlgorithm.aimer256s: kpqc_aimer256s_clear_test_entropy(); break;
    case SignatureAlgorithm.haetae2: kpqc_haetae2_clear_test_entropy(); break;
    case SignatureAlgorithm.haetae3: kpqc_haetae3_clear_test_entropy(); break;
    case SignatureAlgorithm.haetae5: kpqc_haetae5_clear_test_entropy(); break;
    }
}

/// Installs deterministic entropy for a key-encapsulation test.
void setTestEntropy(KemAlgorithm algorithm, const(ubyte)[] input) @trusted
{
    int status;
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768: status = kpqc_ntruplus768_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.ntruPlus864: status = kpqc_ntruplus864_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.ntruPlus1152: status = kpqc_ntruplus1152_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.smaugT128: status = kpqc_smaugt128_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.smaugT192: status = kpqc_smaugt192_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.smaugT256: status = kpqc_smaugt256_set_test_entropy(input.ptr, input.length); break;
    case KemAlgorithm.timer: status = kpqc_timer_set_test_entropy(input.ptr, input.length); break;
    }
    if (status != 0)
        throw new Exception("failed to install deterministic entropy");
}

/// Returns the number of unused deterministic key-encapsulation test bytes.
size_t testEntropyRemaining(KemAlgorithm algorithm) @trusted nothrow
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768: return kpqc_ntruplus768_test_entropy_remaining();
    case KemAlgorithm.ntruPlus864: return kpqc_ntruplus864_test_entropy_remaining();
    case KemAlgorithm.ntruPlus1152: return kpqc_ntruplus1152_test_entropy_remaining();
    case KemAlgorithm.smaugT128: return kpqc_smaugt128_test_entropy_remaining();
    case KemAlgorithm.smaugT192: return kpqc_smaugt192_test_entropy_remaining();
    case KemAlgorithm.smaugT256: return kpqc_smaugt256_test_entropy_remaining();
    case KemAlgorithm.timer: return kpqc_timer_test_entropy_remaining();
    }
}

/// Removes deterministic entropy from a key-encapsulation test.
void clearTestEntropy(KemAlgorithm algorithm) @trusted nothrow
{
    final switch (algorithm)
    {
    case KemAlgorithm.ntruPlus768: kpqc_ntruplus768_clear_test_entropy(); break;
    case KemAlgorithm.ntruPlus864: kpqc_ntruplus864_clear_test_entropy(); break;
    case KemAlgorithm.ntruPlus1152: kpqc_ntruplus1152_clear_test_entropy(); break;
    case KemAlgorithm.smaugT128: kpqc_smaugt128_clear_test_entropy(); break;
    case KemAlgorithm.smaugT192: kpqc_smaugt192_clear_test_entropy(); break;
    case KemAlgorithm.smaugT256: kpqc_smaugt256_clear_test_entropy(); break;
    case KemAlgorithm.timer: kpqc_timer_clear_test_entropy(); break;
    }
}
