package io.softwarity.lib.totp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


@Slf4j
public final class Totp {

    /**
     * The system property to specify the random number generator algorithm to use.
     */
    public static final String RNG_ALGORITHM = "io.softwarity.lib.totp.rng.algorithm";

    /**
     * The system property to specify the random number generator provider to use.
     */
    public static final String RNG_ALGORITHM_PROVIDER = "io.softwarity.lib.totp.rng.algorithmProvider";

    /**
     * Number of digits of a scratch code represented as a decimal integer.
     */
    private static final int SCRATCH_CODE_LENGTH = 8;

    /**
     * Modulus used to truncate the scratch code.
     */
    public static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);

    /**
     * Magic number representing an invalid scratch code.
     */
    private static final int SCRATCH_CODE_INVALID = -1;

    /**
     * Length in bytes of each scratch code. We're using Google's default of
     * using 4 bytes per scratch code.
     */
    private static final int BYTES_PER_SCRATCH_CODE = 4;

    /**
     * The default SecureRandom algorithm to use if none is specified.
     */
    @SuppressWarnings("SpellCheckingInspection")
    private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

    /**
     * The default random number algorithm provider to use if none is specified.
     */
    private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";

    /**
     * The configuration used by the current instance.
     */
    private final TotpConfig config;

    /**
     * The internal SecureRandom instance used by this class. Since Java 7
     * {@link Random} instances are required to be thread-safe, no synchronisation
     * is
     * required in the methods of this class using this instance. Thread-safety
     * of this class was a de-facto standard in previous versions of Java so
     * that it is expected to work correctly in previous versions of the Java
     * platform as well.
     */
    private ReseedingSecureRandom secureRandom;

    /**
     * The constructor that uses the default config, random number algorithm, and
     * random number algorithm provider.
     */
    public Totp() {
        this(new TotpConfig());
    }

    /**
     * The constructor that allows a user to specify the config and uses the default
     * randomNumberAlgorithm and randomNumberAlgorithmProvider.
     *
     * @param config The configuration used by the current instance.
     */
    public Totp(TotpConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null.");
        }
        this.config = config;
        this.secureRandom = new ReseedingSecureRandom(getRandomNumberAlgorithm(), getRandomNumberAlgorithmProvider());
    }

    /**
     * The constructor that allows a user the randomNumberAlgorithm, the
     * randomNumberAlgorithmProvider, and uses the default config.
     *
     * @param randomNumberAlgorithm         The random number algorithm to define
     *                                      the secure random number generator. If
     *                                      this is null the
     *                                      randomNumberAlgorithmProvider must be
     *                                      null.
     * @param randomNumberAlgorithmProvider The random number algorithm provider to
     *                                      define the secure random number
     *                                      generator. This value may be null.
     */
    public Totp(final String randomNumberAlgorithm, final String randomNumberAlgorithmProvider) {
        this(new TotpConfig(), randomNumberAlgorithm, randomNumberAlgorithmProvider);
    }

    /**
     * The constructor that allows a user to specify the config, the
     * randomNumberAlgorithm, and the randomNumberAlgorithmProvider.
     *
     * @param config                        The configuration used by the current
     *                                      instance.
     * @param randomNumberAlgorithm         The random number algorithm to define
     *                                      the secure random number generator. If
     *                                      this is null the
     *                                      randomNumberAlgorithmProvider must be
     *                                      null.
     * @param randomNumberAlgorithmProvider The random number algorithm provider to
     *                                      define the secure random number
     *                                      generator. This value may be null.
     */
    public Totp(TotpConfig config, final String randomNumberAlgorithm, final String randomNumberAlgorithmProvider) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null.");
        }
        this.config = config;
        if (Objects.isNull(randomNumberAlgorithm) && Objects.isNull(randomNumberAlgorithmProvider)) {
            this.secureRandom = new ReseedingSecureRandom();
        } else if (Objects.isNull(randomNumberAlgorithm)) {
            throw new IllegalArgumentException("RandomNumberAlgorithm must not be null. If the RandomNumberAlgorithm is null, the RandomNumberAlgorithmProvider must also be null.");
        } else if (Objects.isNull(randomNumberAlgorithmProvider)) {
            this.secureRandom = new ReseedingSecureRandom(randomNumberAlgorithm);
        }
    }

    public Mono<Boolean> authorize(String secret, int verificationCode) {
        return authorize(secret, verificationCode, new Date().getTime());
    }

    public Mono<Boolean> authorize(String secret, int verificationCode, long time) {
        // Checking user input and failing if the secret key was not provided.
        if (secret == null) {
            throw new IllegalArgumentException("Secret cannot be null.");
        }
        // Checking if the verification code is between the legal bounds.
        if (verificationCode <= 0 || verificationCode >= this.config.getKeyModulus()) {
            return Mono.just(false);
        }
        // Checking the validation code using the current UNIX time.
        return checkCode(secret, verificationCode, time, this.config.getWindowSize());
    }

    /**
     * @return the default random number generator algorithm.
     */
    private String getRandomNumberAlgorithm() {
        return System.getProperty(RNG_ALGORITHM, DEFAULT_RANDOM_NUMBER_ALGORITHM);
    }

    /**
     * @return the default random number generator algorithm provider.
     */
    private String getRandomNumberAlgorithmProvider() {
        return System.getProperty(RNG_ALGORITHM_PROVIDER, DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER);
    }

    /**
     * Calculates the verification code of the provided key at the specified
     * instant of time using the algorithm specified in RFC 6238.
     *
     * @param key the secret key in binary format.
     * @param tm  the instant of time.
     * @return the validation code for the provided key at the specified instant
     *         of time.
     */
    Mono<Integer> calculateCode(byte[] key, long tm) {
        // Allocating an array of bytes to represent the specified instant
        // of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        SecretKeySpec signKey = new SecretKeySpec(key, config.getHmacHashFunction().toString());

        try {
            // Getting an HmacSHA1/HmacSHA256 algorithm implementation from the JCE.
            Mac mac = Mac.getInstance(config.getHmacHashFunction().toString());
            // Initializing the MAC algorithm.
            mac.init(signKey);
            // Processing the instant of time and getting the encrypted data.
            byte[] hash = mac.doFinal(data);
            // Building the validation code performing dynamic truncation
            // (RFC4226, 5.3. Generating an HOTP value)
            int offset = hash[hash.length - 1] & 0xF;
            // We are using a long because Java hasn't got an unsigned integer type
            // and we need 32 unsigned bits).
            long truncatedHash = LongStream.range(0, 4).reduce(0L, (long res, long i) -> {
                res <<= 8;
                // Java bytes are signed, but we need an unsigned integer:
                // cleaning off all but the LSB.
                return res | (hash[offset + (int) i] & 0xFF);
            });
            // Clean bits higher than the 32nd (inclusive) and calculate the
            // module with the maximum validation code value.
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= config.getKeyModulus();
            // Returning the validation code to the caller.
            return Mono.just((int) truncatedHash);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            // Logging the exception.
            log.error(ex.getMessage(), ex);
            // We're not disclosing internal error details to our clients.
            return Mono.error(new TotpException("The operation cannot be performed now."));
        }
    }

    private long getTimeWindowFromTime(long time) {
        return time / this.config.getTimeStepSizeInMillis();
    }

    /**
     * This method implements the algorithm specified in RFC 6238 to check if a
     * validation code is valid in a given instant of time for the given secret
     * key.
     *
     * @param secret    the Base32 encoded secret key.
     * @param code      the code to validate.
     * @param timestamp the instant of time to use during the validation process.
     * @param window    the window size to use during the validation process.
     * @return <code>true</code> if the validation code is valid,
     *         <code>false</code> otherwise.
     */
    private Mono<Boolean> checkCode(String secret, long code, long timestamp, int window) {
        byte[] decodedKey = decodeSecret(secret);
        // convert unix time into a 30 second "window" as specified by the
        // TOTP specification. Using Google's default interval of 30 seconds.
        final long timeWindow = getTimeWindowFromTime(timestamp);
        // Calculating the verification code of the given key in each of the
        // time intervals and returning true if the provided code is equal to
        // one of them.
        return Flux.fromStream(IntStream.rangeClosed(-((window - 1) / 2), window / 2).boxed()).flatMap((Integer i) -> {
          // Calculating the verification code for the current time interval.
          return calculateCode(decodedKey, timeWindow + i).map(Integer::longValue);
        }).any((Long hash) -> {
          // Checking if the provided code is equal to the calculated one.
          return hash.equals(code);
        });
    }

    private byte[] decodeSecret(String secret) {
        // Decoding the secret key to get its raw byte representation.
        switch (config.getKeyRepresentation()) {
            case BASE32:
                Base32 codec32 = new Base32();
                // See: https://issues.apache.org/jira/browse/CODEC-234
                // Commons Codec Base32::decode does not support lowercase letters.
                return codec32.decode(secret.toUpperCase());
            case BASE64:
                Base64 codec64 = new Base64();
                return codec64.decode(secret);
            default:
                throw new IllegalArgumentException("Unknown key representation type.");
        }
    }

    public Mono<TotpKey> createCredentials() {
        // Allocating a buffer sufficiently large to hold the bytes required by
        // the secret key.
        int bufferSize = config.getSecretBits() / 8;
        byte[] buffer = new byte[bufferSize];
        secureRandom.nextBytes(buffer);
        // Extracting the bytes making up the secret key.
        byte[] secretKey = Arrays.copyOf(buffer, bufferSize);
        String generatedKey = calculateSecretKey(secretKey);
        // Generating the verification code at time = 0.
        return calculateValidationCode(secretKey).map((Integer validationCode) -> {
          // Calculate scratch codes
          List<Integer> scratchCodes =calculateScratchCodes();
          return new TotpKey.Builder(generatedKey).setConfig(config).setVerificationCode(validationCode).setScratchCodes(scratchCodes).build();
        });
    }

    private List<Integer> calculateScratchCodes() {
        return Stream.generate(() -> generateScratchCode()).limit(config.getNumberOfScratchCodes()).toList();
    }

    /**
     * This method calculates a scratch code from a random byte buffer of
     * suitable size <code>#BYTES_PER_SCRATCH_CODE</code>.
     *
     * @param scratchCodeBuffer a random byte buffer whose minimum size is
     *                          <code>#BYTES_PER_SCRATCH_CODE</code>.
     * @return the scratch code.
     */
    private int calculateScratchCode(byte[] scratchCodeBuffer) {
        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
            throw new IllegalArgumentException(String.format("The provided random byte buffer is too small: %d.", scratchCodeBuffer.length));
        }

        int scratchCode = IntStream.range(0, BYTES_PER_SCRATCH_CODE).reduce(0, (int res, int i) -> (res << 8) + (scratchCodeBuffer[i] & 0xff));

        scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

        // Accept the scratch code only if it has exactly
        // SCRATCH_CODE_LENGTH digits.
        if (validateScratchCode(scratchCode)) {
            return scratchCode;
        } else {
            return SCRATCH_CODE_INVALID;
        }
    }

    /* package */ boolean validateScratchCode(int scratchCode) {
        return (scratchCode >= SCRATCH_CODE_MODULUS / 10);
    }

    /**
     * This method creates a new random byte buffer from which a new scratch
     * code is generated. This function is invoked if a scratch code generated
     * from the main buffer is invalid because it does not satisfy the scratch
     * code restrictions.
     *
     * @return A valid scratch code.
     */
    private int generateScratchCode() {
        while (true) {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            secureRandom.nextBytes(scratchCodeBuffer);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID) {
                return scratchCode;
            }
        }
    }

    /**
     * This method calculates the validation code at time 0.
     *
     * @param secretKey The secret key to use.
     * @return the validation code at time 0.
     */
    private Mono<Integer> calculateValidationCode(byte[] secretKey) {
        return calculateCode(secretKey, 0);
    }

    public Mono<Integer> getTotpPassword(String secret) {
        return getTotpPassword(secret, new Date().getTime());
    }

    public Mono<Integer> getTotpPassword(String secret, long time) {
        return calculateCode(decodeSecret(secret), getTimeWindowFromTime(time));
    }

    /**
     * This method calculates the secret key given a random byte buffer.
     *
     * @param secretKey a random byte buffer.
     * @return the secret key.
     */
    private String calculateSecretKey(byte[] secretKey) {
        switch (config.getKeyRepresentation()) {
            case BASE32:
                return new Base32().encodeToString(secretKey);
            case BASE64:
                return new Base64().encodeToString(secretKey);
            default:
                throw new IllegalArgumentException("Unknown key representation type.");
        }
    }
}
