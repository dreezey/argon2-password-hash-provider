package be.cronos.keycloak.utils;

import be.cronos.keycloak.exceptions.Argon2RuntimeException;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.jboss.logging.Logger;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2Helper {
    private static final Logger LOG = Logger.getLogger(Argon2Helper.class);

    private Argon2Helper() {
        throw new IllegalStateException("Helper class");
    }

    public static String hashPassword(String rawPassword, Argon2Factory.Argon2Types argon2Variant, int iterations,
                                      int parallelism, int memoryLimit, int hashLength, int saltLength) {
        if (rawPassword == null) throw new Argon2RuntimeException("Password can't be empty");
        Argon2 argon2 = Argon2Factory.createAdvanced(argon2Variant, saltLength, hashLength);
        String hash;

        try {
            // Hash the password
            hash = argon2.hash(iterations, memoryLimit, parallelism, rawPassword.toCharArray());
            return hash;
        } catch (IllegalStateException ise) {
            LOG.errorf("Something is wrong with the parameters, message = '%s'", ise.getMessage());
        } catch (Exception e) {
            LOG.errorf("Something went wrong while hashing the password, message = '%s'", e.getMessage());
        }
        throw new Argon2RuntimeException("Something went wrong while securing the password.");
    }

    public static boolean verifyPassword(String rawPassword, PasswordCredentialModel credential) {
        // Get the Argon2 variant of the credential, should be something like:
        // $argon2i$v=19$m=65535,t=30,p=4$JQUxqirAz7+Em0yM1ZiDFA$LhqtL0XPGESfeHb4lI2XnV4mSZacWGQWANKtvIVVpy4
        // however, the variant's case is not correct for the enum
        String storedVariant = credential.getPasswordSecretData().getValue().split("\\$")[1];
        Argon2Factory.Argon2Types storedArgon2Variant = null;
        try {
            for (Argon2Factory.Argon2Types argon2Type : Argon2Factory.Argon2Types.values()) {
                if (argon2Type.toString().equalsIgnoreCase(storedVariant)) {
                    storedArgon2Variant = argon2Type;
                    LOG.debugf("Stored variant found: %s", storedVariant);
                }
            }
            if (storedArgon2Variant == null) throw new Argon2RuntimeException("Unknown stored Argon2 variant");
        } catch (Argon2RuntimeException e) {
            throw new Argon2RuntimeException(e.getMessage());
        }

        // Now make sure to select the correct variant for the Argon2Factory
        Argon2 argon2 = Argon2Factory.createAdvanced(storedArgon2Variant);

        boolean samePassword = false;
        try {
            if (argon2.verify(credential.getPasswordSecretData().getValue(), rawPassword.toCharArray())) {
                LOG.debugf("Passwords match!!");
                samePassword = true;
            } else {
                LOG.debugf("Passwords don't match!!");
            }
        } catch (Exception e) {
            LOG.errorf("Couldn't compare password, exception occurred: %s", e.getMessage());
        }
        return samePassword;
    }
}
