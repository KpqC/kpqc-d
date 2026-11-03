module main;

import std.file : readText;
import std.path : buildPath;
import std.process : environment;
import std.stdio : writefln, writeln;
import std.string : indexOf, splitLines, strip;

import kpqc;
import kpqc.testing;

private alias Vector = string[string];

private struct Drbg
{
    ubyte[] key;
    ubyte[] counter;
}

private struct SignatureConfiguration
{
    SignatureAlgorithm algorithm;
    string path;
    bool isHaetae;
    size_t seedBytes;
}

private struct KemConfiguration
{
    KemAlgorithm algorithm;
    string path;
    size_t keyCalls;
    size_t encapsulationBytes;
}

private void require(bool condition, lazy string message)
{
    if (!condition)
        throw new Exception(message);
}

private ubyte hexDigit(char value)
{
    if (value >= '0' && value <= '9')
        return cast(ubyte)(value - '0');
    if (value >= 'a' && value <= 'f')
        return cast(ubyte)(value - 'a' + 10);
    if (value >= 'A' && value <= 'F')
        return cast(ubyte)(value - 'A' + 10);
    throw new Exception("invalid hexadecimal digit");
}

private ubyte[] hexToBytes(string value)
{
    require(value.length % 2 == 0, "hex value has an odd length");
    auto result = new ubyte[value.length / 2];
    foreach (index; 0 .. result.length)
        result[index] = cast(ubyte)((hexDigit(value[index * 2]) << 4)
            | hexDigit(value[index * 2 + 1]));
    return result;
}

private Vector[] readVectors(string path)
{
    Vector[] result;
    Vector current;
    foreach (line; readText(path).splitLines)
    {
        const separator = line.indexOf(" = ");
        if (separator < 0)
            continue;
        const name = line[0 .. separator].strip;
        const value = line[separator + 3 .. $];
        if (name == "count" && current.length != 0)
        {
            result ~= current;
            current = null;
        }
        current[name] = value;
    }
    if (current.length != 0)
        result ~= current;
    return result;
}

private ubyte[] field(ref Vector vector, string name)
{
    require((name in vector) !is null, "missing vector field: " ~ name);
    return hexToBytes(vector[name]);
}

private ubyte[] xorBytes(const(ubyte)[] left, const(ubyte)[] right)
{
    require(left.length == right.length, "XOR inputs have different lengths");
    auto result = new ubyte[left.length];
    foreach (index; 0 .. result.length)
        result[index] = cast(ubyte)(left[index] ^ right[index]);
    return result;
}

private void incrementCounter(ref ubyte[] counter)
{
    auto index = counter.length;
    while (index != 0)
    {
        --index;
        ++counter[index];
        if (counter[index] != 0)
            break;
    }
}

private ubyte[] generateBlocks(ref Drbg state, size_t count)
{
    ubyte[] result;
    result.reserve(count * 16);
    foreach (_; 0 .. count)
    {
        incrementCounter(state.counter);
        result ~= aes256Ecb(state.key, state.counter);
    }
    return result;
}

private void update(ref Drbg state, const(ubyte)[] provided)
{
    require(provided.length <= 48, "DRBG update data exceeds 48 bytes");
    auto padded = new ubyte[48];
    padded[0 .. provided.length] = provided[];
    const material = xorBytes(generateBlocks(state, 3), padded);
    state.key = material[0 .. 32].dup;
    state.counter = material[32 .. 48].dup;
}

private Drbg newDrbg(const(ubyte)[] seed)
{
    require(seed.length == 48, "CTR-DRBG seed must contain 48 bytes");
    Drbg result;
    result.key = new ubyte[32];
    result.counter = new ubyte[16];
    result.update(seed);
    return result;
}

private Drbg copyDrbg(ref Drbg state)
{
    return Drbg(state.key.dup, state.counter.dup);
}

private ubyte[] generate(ref Drbg state, size_t length)
{
    const blocks = (length + 15) / 16;
    const output = generateBlocks(state, blocks);
    state.update(null);
    return output[0 .. length].dup;
}

private T withExactEntropy(A, T)(A algorithm, const(ubyte)[] entropy,
    scope T delegate() operation)
{
    algorithm.setTestEntropy(entropy);
    scope (exit) algorithm.clearTestEntropy;
    auto result = operation();
    require(algorithm.testEntropyRemaining == 0,
        "deterministic entropy was not fully consumed");
    return result;
}

private T withRepeatedEntropy(A, T)(A algorithm, ref Drbg state,
    size_t callBytes, scope T delegate() operation)
{
    auto probe = copyDrbg(state);
    ubyte[] entropy;
    entropy.reserve(128 * callBytes);
    foreach (_; 0 .. 128)
        entropy ~= probe.generate(callBytes);

    algorithm.setTestEntropy(entropy);
    scope (exit) algorithm.clearTestEntropy;
    auto result = operation();
    const consumed = entropy.length - algorithm.testEntropyRemaining;
    require(consumed > 0, "deterministic entropy was not consumed");
    require(consumed % callBytes == 0,
        "deterministic entropy consumption was not aligned");
    foreach (_; 0 .. consumed / callBytes)
        state.generate(callBytes);
    return result;
}

void main()
{
    const vectorRoot = environment.get("KPQC_TEST_VECTORS", "");
    require(vectorRoot.length != 0, "KPQC_TEST_VECTORS is not set");

    immutable signatureConfigurations = [
        SignatureConfiguration(SignatureAlgorithm.aimer128f, "aimer/128f", false, 16),
        SignatureConfiguration(SignatureAlgorithm.aimer128s, "aimer/128s", false, 16),
        SignatureConfiguration(SignatureAlgorithm.aimer192f, "aimer/192f", false, 24),
        SignatureConfiguration(SignatureAlgorithm.aimer192s, "aimer/192s", false, 24),
        SignatureConfiguration(SignatureAlgorithm.aimer256f, "aimer/256f", false, 32),
        SignatureConfiguration(SignatureAlgorithm.aimer256s, "aimer/256s", false, 32),
        SignatureConfiguration(SignatureAlgorithm.haetae2, "haetae/mode2", true, 32),
        SignatureConfiguration(SignatureAlgorithm.haetae3, "haetae/mode3", true, 32),
        SignatureConfiguration(SignatureAlgorithm.haetae5, "haetae/mode5", true, 32),
    ];
    immutable kemConfigurations = [
        KemConfiguration(KemAlgorithm.ntruPlus768, "ntruplus/768", 0, 96),
        KemConfiguration(KemAlgorithm.ntruPlus864, "ntruplus/864", 0, 108),
        KemConfiguration(KemAlgorithm.ntruPlus1152, "ntruplus/1152", 0, 144),
        KemConfiguration(KemAlgorithm.smaugT128, "smaugt/mode1", 2, 32),
        KemConfiguration(KemAlgorithm.smaugT192, "smaugt/mode3", 2, 32),
        KemConfiguration(KemAlgorithm.smaugT256, "smaugt/mode5", 2, 32),
        KemConfiguration(KemAlgorithm.timer, "smaugt/modet", 2, 16),
    ];

    size_t total;
    foreach (configuration; signatureConfigurations)
    {
        auto vectors = readVectors(buildPath(vectorRoot,
            configuration.path, "kat.rsp"));
        require(vectors.length == 100,
            configuration.path ~ " must contain 100 vectors");
        foreach (ref vector; vectors)
        {
            auto state = newDrbg(vector.field("seed"));
            KeyPair keys;
            if (configuration.isHaetae)
                keys = configuration.algorithm.withExactEntropy(
                    state.generate(configuration.seedBytes),
                    () => configuration.algorithm.generateKeyPair);
            else
                keys = configuration.algorithm.withRepeatedEntropy(state,
                    configuration.seedBytes,
                    () => configuration.algorithm.generateKeyPair);

            require(keys.publicKey == vector.field("pk"),
                configuration.path ~ " public key mismatch");
            require(keys.secretKey == vector.field("sk"),
                configuration.path ~ " secret key mismatch");

            const message = vector.field("msg");
            ubyte[] expectedSignature;
            if ("sig" in vector)
                expectedSignature = vector.field("sig");
            else
            {
                const signedMessage = vector.field("sm");
                expectedSignature = signedMessage[message.length .. $].dup;
            }
            const signingEntropy = state.generate(configuration.seedBytes);
            ubyte[] context;
            if (configuration.isHaetae)
            {
                const contextLength = state.generate(1)[0];
                context = state.generate(contextLength);
            }
            const signature = configuration.algorithm.withExactEntropy(
                signingEntropy, () => configuration.algorithm.sign(
                    message, keys.secretKey, context));
            require(signature == expectedSignature,
                configuration.path ~ " signature mismatch");
            require(configuration.algorithm.verify(message, expectedSignature,
                keys.publicKey, context),
                configuration.path ~ " signature verification failed");
        }
        total += vectors.length;
        writefln("KAT passed: %s", configuration.path);
    }

    foreach (configuration; kemConfigurations)
    {
        auto vectors = readVectors(buildPath(vectorRoot,
            configuration.path, "kat.rsp"));
        require(vectors.length == 100,
            configuration.path ~ " must contain 100 vectors");
        foreach (ref vector; vectors)
        {
            auto state = newDrbg(vector.field("seed"));
            KeyPair keys;
            if (configuration.keyCalls == 0)
                keys = configuration.algorithm.withRepeatedEntropy(state, 32,
                    () => configuration.algorithm.generateKeyPair);
            else
            {
                ubyte[] entropy;
                entropy.reserve(configuration.keyCalls * 32);
                foreach (_; 0 .. configuration.keyCalls)
                    entropy ~= state.generate(32);
                keys = configuration.algorithm.withExactEntropy(entropy,
                    () => configuration.algorithm.generateKeyPair);
            }
            require(keys.publicKey == vector.field("pk"),
                configuration.path ~ " public key mismatch");
            require(keys.secretKey == vector.field("sk"),
                configuration.path ~ " secret key mismatch");

            const outbound = configuration.algorithm.withExactEntropy(
                state.generate(configuration.encapsulationBytes),
                () => configuration.algorithm.encapsulate(keys.publicKey));
            require(outbound.ciphertext == vector.field("ct"),
                configuration.path ~ " ciphertext mismatch");
            require(outbound.sharedSecret == vector.field("ss"),
                configuration.path ~ " shared secret mismatch");
            require(configuration.algorithm.decapsulate(outbound.ciphertext,
                keys.secretKey) == outbound.sharedSecret,
                configuration.path ~ " decapsulation mismatch");
        }
        total += vectors.length;
        writefln("KAT passed: %s", configuration.path);
    }

    require(total == 1_600, "expected 1,600 vectors");
    writeln("All 1,600 known-answer records passed");
}
