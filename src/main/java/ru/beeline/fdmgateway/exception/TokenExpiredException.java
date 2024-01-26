package ru.beeline.fdmgateway.exception;

public class TokenExpiredException extends Exception {
    public TokenExpiredException(String message) {
        super(message);
    }
}
