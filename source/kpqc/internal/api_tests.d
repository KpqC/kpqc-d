module kpqc.internal.api_tests;

version (unittest)
{
    import std.exception : assertThrown;

    import kpqc;

    private ubyte[] changedFirst(const(ubyte)[] value)
    {
        auto result = value.dup;
        if (result.length != 0)
            result[0] ^= 1;
        return result;
    }

    private ubyte[] filled(size_t length, ubyte value)
    {
        auto result = new ubyte[length];
        result[] = value;
        return result;
    }

    unittest
    {
        immutable ubyte[] message = [0x00, 0x01, 0x7f, 0x80, 0xff];
        immutable ubyte[] context = [0x6b, 0x70, 0x71, 0x63];

        foreach (algorithm; signatureAlgorithms)
        {
            const parameterSizes = algorithm.sizes;
            const keys = algorithm.generateKeyPair;
            const signature = algorithm.sign(message, keys.secretKey, context);

            assert(keys.publicKey.length == parameterSizes.publicKey);
            assert(keys.secretKey.length == parameterSizes.secretKey);
            assert(signature.length == parameterSizes.signature);
            assert(algorithm.verify(message, signature, keys.publicKey,
                context));
            assert(!algorithm.verify(changedFirst(message), signature,
                keys.publicKey, context));
            assert(!algorithm.verify(message, changedFirst(signature),
                keys.publicKey, context));
            assert(!algorithm.verify(message, signature, keys.publicKey,
                [cast(ubyte) 0x00]));
            assert(!algorithm.verify(message, signature[0 .. $ - 1],
                keys.publicKey, context));
        }

        foreach (algorithm; kemAlgorithms)
        {
            const parameterSizes = algorithm.sizes;
            const keys = algorithm.generateKeyPair;
            const outbound = algorithm.encapsulate(keys.publicKey);
            const inbound = algorithm.decapsulate(outbound.ciphertext,
                keys.secretKey);

            assert(keys.publicKey.length == parameterSizes.publicKey);
            assert(keys.secretKey.length == parameterSizes.secretKey);
            assert(outbound.ciphertext.length == parameterSizes.ciphertext);
            assert(outbound.sharedSecret.length == parameterSizes.sharedSecret);
            assert(inbound == outbound.sharedSecret);

            const changedCiphertext = changedFirst(outbound.ciphertext);
            final switch (algorithm)
            {
            case KemAlgorithm.ntruPlus768:
            case KemAlgorithm.ntruPlus864:
            case KemAlgorithm.ntruPlus1152:
                assertThrown!KpqCException(algorithm.decapsulate(
                    changedCiphertext, keys.secretKey));
                assertThrown!KpqCException(algorithm.encapsulate(
                    filled(parameterSizes.publicKey, ubyte.max)));
                break;
            case KemAlgorithm.smaugT128:
            case KemAlgorithm.smaugT192:
            case KemAlgorithm.smaugT256:
            case KemAlgorithm.timer:
                const replacement = algorithm.decapsulate(changedCiphertext,
                    keys.secretKey);
                assert(replacement.length == parameterSizes.sharedSecret);
                assert(replacement != outbound.sharedSecret);
                break;
            }
        }

        assertThrown!KpqCException(SignatureAlgorithm.aimer128f.sign(
            [cast(ubyte) 1], new ubyte[47]));
        assertThrown!KpqCException(SignatureAlgorithm.aimer128f.verify(
            null, new ubyte[6_944], new ubyte[31]));
        assertThrown!KpqCException(KemAlgorithm.smaugT128.encapsulate(
            new ubyte[671]));
        assertThrown!KpqCException(KemAlgorithm.smaugT128.decapsulate(
            new ubyte[672], new ubyte[831]));

        const keys = SignatureAlgorithm.aimer128f.generateKeyPair;
        assertThrown!KpqCException(SignatureAlgorithm.aimer128f.sign(
            null, keys.secretKey, new ubyte[256]));
        assertThrown!KpqCException(SignatureAlgorithm.aimer128f.verify(
            null, new ubyte[6_944], keys.publicKey, new ubyte[256]));
    }
}
