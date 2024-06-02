package io.softwarity.lib.totp;

public class TotpException extends RuntimeException {

    public TotpException(String message) {
        super(message);
    }

    public TotpException(String message, Throwable cause) {
        super(message, cause);
    }
}
