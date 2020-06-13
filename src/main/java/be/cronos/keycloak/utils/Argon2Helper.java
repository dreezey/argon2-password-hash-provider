package be.cronos.keycloak.utils;

import be.cronos.keycloak.enums.Argon2Variant;
import be.cronos.keycloak.exceptions.Argon2RuntimeException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Strings;
import org.jboss.logging.Logger;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2Helper {
    private static final Logger LOG = Logger.getLogger(Argon2Helper.class);

    private Argon2Helper() {
        throw new IllegalStateException("Helper class");
    }

    public static String hashPassword(String rawPassword, byte[] salt, Argon2Variant argon2Variant, int version,
                                      int iterations, int parallelism, int memoryLimit, int hashLength) {

        if (rawPassword == null) throw new Argon2RuntimeException("Password can't be empty");

        // Validate whether the version is valid
        if (version != org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_10 && version != org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
            throw new Argon2RuntimeException("Invalid version");

        LOG.debugf("Using the following Argon2 settings:");
        LOG.debugf("\tArgon2 Variant: %s", argon2Variant.getArgon2VariantStringRepr());
        LOG.debugf("\tIterations: %d", iterations);
        LOG.debugf("\tVersion: %h", version);
        LOG.debugf("\tParallelism: %d", parallelism);
        LOG.debugf("\tMemory limit: %d", memoryLimit);
        LOG.debugf("\tHash Length: %d", hashLength);
        LOG.debugf("\tSalt Length: %d", salt.length);

        try {
            // Construct the Argon2 Parameters Builder
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argon2Variant.getArgon2BouncyCastle())
                    .withSalt(salt)
                    .withVersion(version)
                    .withIterations(iterations)
                    .withParallelism(parallelism)
                    .withMemoryAsKB(memoryLimit);

            // Initialize BouncyCastle's Argon2 generator
            Argon2BytesGenerator generator = new Argon2BytesGenerator();

            // Initialize the digest generator
            generator.init(builder.build());

            // Digest bytes result output
            byte[] result = new byte[hashLength];

            // Keep track of hashing runtime
            long start = System.currentTimeMillis();

            // Perform the hashing
            generator.generateBytes(rawPassword.toCharArray(), result, 0, result.length);

            // Stop timing
            long end = System.currentTimeMillis();

            // Print the hashing runtime for debug purposes
            LOG.debugf("Hashing runtime was %d milliseconds (%d seconds).", end-start, (end-start)/1000);

            // Return an encoded representation of the argon2 password hash
            return String.format("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
                    argon2Variant.getArgon2VariantStringRepr(),
                    version,
                    memoryLimit,
                    iterations,
                    parallelism,
                    Base64.getEncoder().withoutPadding().encodeToString(salt),
                    Base64.getEncoder().withoutPadding().encodeToString(result)
            );
        } catch (Exception e) {
            LOG.errorf("Something went wrong while hashing the password, message = '%s'", e.getMessage());
        }
        throw new Argon2RuntimeException("Something went wrong while securing the password.");
    }

    public static boolean verifyPassword(String rawPassword, PasswordCredentialModel credential) {
        // Get the Argon2 parameters of the credential, should be something like:
        // $argon2i$v=19$m=65535,t=30,p=4$JQUxqirAz7+Em0yM1ZiDFA$LhqtL0XPGESfeHb4lI2XnV4mSZacWGQWANKtvIVVpy4
        // Retrieve the stored encoded password
        String storedEncodedPassword = credential.getPasswordSecretData().getValue();
        // Retrieved the salt
        byte[] salt = credential.getPasswordSecretData().getSalt();
        // Extract all the stored parameters
        Argon2EncodingUtils.Argon2Parameters argon2Parameters = Argon2EncodingUtils.extractArgon2ParametersFromEncodedPassword(storedEncodedPassword);

        // Extract the digest
        String storedPasswordDigest = Argon2EncodingUtils.extractDigest(storedEncodedPassword);
        if (storedPasswordDigest == null) {
            LOG.errorf("There's something wrong with the stored password encoding, couldn't find the actual hash.");
            throw new Argon2RuntimeException("Something went wrong.");
        }

        // Hash the incoming password (according to stored password's parameters)
        String attemptedEncodedPassword = hashPassword(
                rawPassword,
                salt,
                argon2Parameters.getArgon2Variant(),
                argon2Parameters.getVersion(),
                argon2Parameters.getIterations(),
                argon2Parameters.getParallelism(),
                argon2Parameters.getMemory(),
                argon2Parameters.getHashLength()
        );

        // Extract the digest of the attempted hashed password
        String attemptedPasswordDigest = Argon2EncodingUtils.extractDigest(attemptedEncodedPassword);
        if (attemptedPasswordDigest == null) {
            LOG.errorf("There's something wrong with the attempted password encoding, couldn't find the actual hash.");
            throw new Argon2RuntimeException("Something went wrong.");
        }

        // Compare the 2 digests using constant-time comparison
        boolean samePassword = MessageDigest.isEqual(Strings.toByteArray(storedPasswordDigest), Strings.toByteArray(attemptedPasswordDigest));

        LOG.debugf("Password match = %s", String.valueOf(samePassword));

        return samePassword;
    }

    public static byte[] getSalt(int saltLength) {
        LOG.debugf("Generating salt with length '%d'.", saltLength);
        byte[] buffer = new byte[saltLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }
}
