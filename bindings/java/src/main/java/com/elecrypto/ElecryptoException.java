package com.elecrypto;

/**
 * Exception thrown by Elecrypto operations
 */
public class ElecryptoException extends Exception {
    private final int errorCode;

    public ElecryptoException(int errorCode, String message) {
        super(message + " (error code: " + errorCode + ")");
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
