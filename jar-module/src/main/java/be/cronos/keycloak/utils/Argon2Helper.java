package be.cronos.keycloak.utils;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.jboss.logging.Logger;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2Helper {
    private static final Logger LOG = Logger.getLogger(Argon2Helper.class);

    public static String hashPassword(String rawPassword, Argon2Factory.Argon2Types argon2Variant, int iterations,
                                      int parallelism, int memoryLimit, int hashLength, int saltLength) {
        if (rawPassword == null) throw new RuntimeException("Password can't be empty");
        Argon2 argon2 = Argon2Factory.createAdvanced(argon2Variant, saltLength, hashLength);
        String hash;

        try {
            // Hash the password
            hash = argon2.hash(iterations, memoryLimit, parallelism, rawPassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return hash;
    }

    public static boolean verifyPassword(String rawPassword,
                                         PasswordCredentialModel credential) {
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
            if (storedArgon2Variant == null) throw new Exception("Unknown stored Argon2 variant");
        } catch (Exception e) {
            throw new RuntimeException("Unknown stored Argon2 variant, is someone spoofing?");
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
            LOG.debugf("Couldn't compare password, exception occurred: %s", e.getMessage());
        }
        return samePassword;
    }
}
