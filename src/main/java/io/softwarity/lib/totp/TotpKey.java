package io.softwarity.lib.totp;

import java.util.ArrayList;
import java.util.List;

public final class TotpKey {
    /**
     * The configuration of this key.
     */
    private final TotpConfig config;

    /**
     * The secret key in Base32 encoding.
     */
    private final String key;

    /**
     * The verification code at time = 0 (the UNIX epoch).
     */
    private final int verificationCode;

    /**
     * The list of scratch codes.
     */
    private final List<Integer> scratchCodes;

    /**
     * The private constructor of this class.
     *
     * @param config           the configuration of the TOTP algorithm.
     * @param key              the secret key in Base32 encoding.
     * @param verificationCode the verification code at time = 0 (the UNIX epoch).
     * @param scratchCodes     the list of scratch codes.
     */
    private TotpKey(TotpConfig config, String key, int verificationCode, List<Integer> scratchCodes) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        if (scratchCodes == null) {
            throw new IllegalArgumentException("Scratch codes cannot be null");
        }

        this.config = config;
        this.key = key;
        this.verificationCode = verificationCode;
        this.scratchCodes = new ArrayList<>(scratchCodes);
    }

    /**
     * Get the list of scratch codes.
     *
     * @return the list of scratch codes.
     */
    public List<Integer> getScratchCodes() {
        return scratchCodes;
    }

    /**
     * Get the config of this key.
     *
     * @return the config of this key.
     */
    public TotpConfig getConfig() {
        return config;
    }

    /**
     * Returns the secret key in Base32 encoding.
     *
     * @return the secret key in Base32 encoding.
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the verification code at time = 0 (the UNIX epoch).
     *
     * @return the verificationCode at time = 0 (the UNIX epoch).
     */
    public int getVerificationCode() {
        return verificationCode;
    }

    /**
     * This class is a builder to create instances of the
     * {@link TotpKey} class.
     */
    public static class Builder {
        private TotpConfig config = new TotpConfig();
        private String key;
        private int verificationCode;
        private List<Integer> scratchCodes = new ArrayList<>();

        /**
         * Creates an instance of the builder.
         *
         * @param key the secret key in Base32 encoding.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public Builder(String key) {
            this.key = key;
        }

        /**
         * Creates an instance of the {@link TotpKey} class.
         *
         * @return an instance of the {@link TotpKey} class initialized *         with the properties set in this builder.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public TotpKey build() {
            return new TotpKey(config, key, verificationCode, scratchCodes);
        }

        /**
         * Sets the config of the TOTP algorithm for this key.
         *
         * @param config the config of the TOTP algorithm for this key.
         * @return the builder.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public Builder setConfig(TotpConfig config) {
            this.config = config;
            return this;
        }

        /**
         * Sets the secret key.
         *
         * @param key the secret key.
         * @return the builder.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public Builder setKey(String key) {
            this.key = key;
            return this;
        }

        /**
         * Sets the verification code.
         *
         * @param verificationCode the verification code.
         * @return the builder.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public Builder setVerificationCode(int verificationCode) {
            this.verificationCode = verificationCode;
            return this;
        }

        /**
         * Sets the scratch codes.
         *
         * @param scratchCodes the scratch codes.
         * @return the builder.
         * @see TotpKey#TotpKey(TotpConfig, String, int, List)
         */
        public Builder setScratchCodes(List<Integer> scratchCodes) {
            this.scratchCodes = scratchCodes;
            return this;
        }
    }
}
