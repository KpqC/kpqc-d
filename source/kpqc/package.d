module kpqc;

import core.stdc.string : memset;
import std.format : format;

public import kpqc.types;
import kpqc.internal.native;

/// Raised for invalid arguments or failed native cryptographic operations.
class KpqCException : Exception
{
    /// Creates an exception with a diagnostic message.
    this(string message)
    {
        super(message);
    }
}

/// A public and secret key pair.
struct KeyPair
{
    /// Encoded public key.
    ubyte[] publicKey;
    /// Encoded secret key.
    ubyte[] secretKey;
}

/// A KEM ciphertext and its corresponding shared secret.
struct Encapsulation
{
    /// Encoded ciphertext sent to the recipient.
    ubyte[] ciphertext;
    /// Shared secret established with the recipient.
    ubyte[] sharedSecret;
}

private void requireLength(const(ubyte)[] value, size_t expected,
    string name)
{
    if (value.length != expected)
        throw new KpqCException(format("%s must contain %s bytes; received %s",
            name, expected, value.length));
}

private void requireContext(const(ubyte)[] context)
{
    if (context.length > ubyte.max)
        throw new KpqCException("context must contain at most 255 bytes");
}

private void wipe(ubyte[] value) nothrow @trusted
{
    if (value.length != 0)
        memset(value.ptr, 0, value.length);
}

private KpqCException operationError(string operation,
    SignatureAlgorithm algorithm)
{
    return new KpqCException(format("%s failed for %s", operation,
        algorithmName(algorithm)));
}

private KpqCException operationError(string operation, KemAlgorithm algorithm)
{
    return new KpqCException(format("%s failed for %s", operation,
        algorithmName(algorithm)));
}

/// Generates a key pair for a signature parameter set.
KeyPair generateKeyPair(SignatureAlgorithm algorithm) @trusted
{
    const parameterSizes = algorithm.sizes;
    KeyPair result;
    result.publicKey = new ubyte[parameterSizes.publicKey];
    result.secretKey = new ubyte[parameterSizes.secretKey];
    if (signatureKeyPair(algorithm, result.publicKey.ptr,
            result.secretKey.ptr) != 0)
    {
        wipe(result.secretKey);
        throw operationError("key generation", algorithm);
    }
    return result;
}

/// Signs a message with an optional domain-separation context.
ubyte[] sign(SignatureAlgorithm algorithm, const(ubyte)[] message,
    const(ubyte)[] secretKey, const(ubyte)[] context = null) @trusted
{
    const parameterSizes = algorithm.sizes;
    requireLength(secretKey, parameterSizes.secretKey, "secret key");
    requireContext(context);

    auto signature = new ubyte[parameterSizes.signature];
    ulong signatureLength;
    if (signatureSign(algorithm, signature.ptr, &signatureLength,
            message.ptr, message.length, context.ptr, context.length,
            secretKey.ptr) != 0 || signatureLength != signature.length)
        throw operationError("signing", algorithm);
    return signature;
}

/// Verifies a signature using the supplied domain-separation context.
bool verify(SignatureAlgorithm algorithm, const(ubyte)[] message,
    const(ubyte)[] signature, const(ubyte)[] publicKey,
    const(ubyte)[] context = null) @trusted
{
    const parameterSizes = algorithm.sizes;
    requireLength(publicKey, parameterSizes.publicKey, "public key");
    requireContext(context);
    if (signature.length != parameterSizes.signature)
        return false;
    return signatureVerify(algorithm, signature.ptr, signature.length,
        message.ptr, message.length, context.ptr, context.length,
        publicKey.ptr) == 0;
}

/// Generates a key pair for a key encapsulation parameter set.
KeyPair generateKeyPair(KemAlgorithm algorithm) @trusted
{
    const parameterSizes = algorithm.sizes;
    KeyPair result;
    result.publicKey = new ubyte[parameterSizes.publicKey];
    result.secretKey = new ubyte[parameterSizes.secretKey];
    if (kemKeyPair(algorithm, result.publicKey.ptr, result.secretKey.ptr) != 0)
    {
        wipe(result.secretKey);
        throw operationError("key generation", algorithm);
    }
    return result;
}

/// Encapsulates a fresh shared secret for a public key.
Encapsulation encapsulate(KemAlgorithm algorithm,
    const(ubyte)[] publicKey) @trusted
{
    const parameterSizes = algorithm.sizes;
    requireLength(publicKey, parameterSizes.publicKey, "public key");

    Encapsulation result;
    result.ciphertext = new ubyte[parameterSizes.ciphertext];
    result.sharedSecret = new ubyte[parameterSizes.sharedSecret];
    if (kemEncapsulate(algorithm, result.ciphertext.ptr,
            result.sharedSecret.ptr, publicKey.ptr) != 0)
    {
        wipe(result.sharedSecret);
        throw operationError("encapsulation", algorithm);
    }
    return result;
}

/// Decapsulates a shared secret with the recipient's secret key.
ubyte[] decapsulate(KemAlgorithm algorithm, const(ubyte)[] ciphertext,
    const(ubyte)[] secretKey) @trusted
{
    const parameterSizes = algorithm.sizes;
    requireLength(ciphertext, parameterSizes.ciphertext, "ciphertext");
    requireLength(secretKey, parameterSizes.secretKey, "secret key");

    auto sharedSecret = new ubyte[parameterSizes.sharedSecret];
    if (kemDecapsulate(algorithm, sharedSecret.ptr, ciphertext.ptr,
            secretKey.ptr) != 0)
    {
        wipe(sharedSecret);
        throw operationError("decapsulation", algorithm);
    }
    return sharedSecret;
}
