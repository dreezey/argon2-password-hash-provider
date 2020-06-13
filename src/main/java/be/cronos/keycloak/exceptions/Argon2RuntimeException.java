package be.cronos.keycloak.exceptions;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2RuntimeException extends RuntimeException {
    public Argon2RuntimeException() {
    }

    public Argon2RuntimeException(String message) {
        super(message);
    }

    public Argon2RuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public Argon2RuntimeException(Throwable cause) {
        super(cause);
    }

    public Argon2RuntimeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
