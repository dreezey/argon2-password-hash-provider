package be.cronos.keycloak.utils;

import be.cronos.keycloak.enums.Argon2Variant;
import be.cronos.keycloak.exceptions.Argon2RuntimeException;
import be.cronos.keycloak.policy.Argon2HashLengthPasswordPolicyProviderFactory;
import be.cronos.keycloak.policy.Argon2SaltLengthPasswordPolicyProviderFactory;
import org.jboss.logging.Logger;

import java.util.Base64;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2EncodingUtils {
    private static final Logger LOG = Logger.getLogger(Argon2EncodingUtils.class);

    private Argon2EncodingUtils() {
        // noop
    }

    public static String extractDigest(String encodedPassword) {
        String[] explodedEncodedPassword = encodedPassword.split("\\$");
        if (explodedEncodedPassword.length == 0) return null;
        // Digest is always the last value in the split
        return explodedEncodedPassword[explodedEncodedPassword.length-1];
    }

    public static Argon2EncodingUtils.Argon2Parameters extractArgon2ParametersFromEncodedPassword(String encodedPassword) {
        // Declare separate fields which are contained within the encoded password hash
        Argon2Variant storedArgon2Variant;
        int version;
        int memory;
        int iterations;
        int parallelism;
        int hashLength;
        // Now attempt to extract all the parameters
        try {
            storedArgon2Variant = Argon2Variant.parseVariant(encodedPassword.split("\\$")[1]);
            version = extractVersion(encodedPassword);
            memory = extractMemory(encodedPassword);
            iterations = extractIterations(encodedPassword);
            parallelism = extractParallelism(encodedPassword);
            hashLength = getDigestLength(extractDigest(encodedPassword));
            if (storedArgon2Variant == null) throw new Argon2RuntimeException("Unknown stored Argon2 variant");
        } catch (Exception e) {
            throw new Argon2RuntimeException(e.getMessage());
        }
        // If we reach this point, all parameters were found and we return the Argon2Parameters carry object
        return new Argon2EncodingUtils.Argon2Parameters(storedArgon2Variant, version, memory, iterations, parallelism, hashLength);
    }

    public static int extractVersion(String encodedPassword) {
        int version;
        try {
            String[] exploded = encodedPassword.split("\\$");
            String versionPart = exploded[2];
            version = Integer.parseInt(versionPart.split("=")[1]);
        } catch (Exception e) {
            LOG.errorf("Error parsing version from encoded hash: %s", e.getMessage());
            throw new Argon2RuntimeException("Could not extract version from encoded hash.");
        }
        return version;
    }

    public static int extractMemory(String encodedPassword) {
        return Integer.parseInt(extractValue(
                extractParameter(encodedPassword, 0)
        ));
    }

    public static int extractIterations(String encodedPassword) {
        return Integer.parseInt(extractValue(
                extractParameter(encodedPassword, 1)
        ));
    }

    public static int extractParallelism(String encodedPassword) {
        return Integer.parseInt(extractValue(
                extractParameter(encodedPassword, 2)
        ));
    }

    public static int getDigestLength(String base64EncodedString) {
        return Base64.getDecoder().decode(base64EncodedString).length;
    }

    private static String extractParameter(String encodedPassword, int index) {
        String parameters = extractParameters(encodedPassword);
        String[] explodedParameters = parameters.split(",");
        if (explodedParameters.length != 3) throw new Argon2RuntimeException("Encoded hash parameters did not split in 3.");
        return explodedParameters[index];
    }

    private static String extractParameters(String encodedPassword) {
        try {
            return encodedPassword.split("\\$")[3];
        } catch (Exception e) {
            LOG.errorf("Failed to extract parameters from encoded hash.");
            throw new Argon2RuntimeException("Failed to extract parameters from encoded hash.");
        }
    }

    private static String extractValue(String parameter) {
        String[] explodedParameter = parameter.split("=");
        if (explodedParameter.length != 2) throw new Argon2RuntimeException(String.format("'%s' is not a valid 'key=value' parameter.", parameter));
        return explodedParameter[1];
    }

    public static class Argon2Parameters {
        private final Argon2Variant argon2Variant;
        private final int version;
        private final int memory;
        private final int iterations;
        private final int parallelism;
        private final int hashLength;
        private final int saltLength;

        public Argon2Parameters(Argon2Variant argon2Variant, int version, int memory, int iterations, int parallelism) {
            this(argon2Variant, version, memory, iterations, parallelism, Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH, Argon2SaltLengthPasswordPolicyProviderFactory.DEFAULT_SALT_LENGTH);
        }

        public Argon2Parameters(Argon2Variant argon2Variant, int version, int memory, int iterations, int parallelism, int hashLength) {
            this(argon2Variant, version, memory, iterations, parallelism, hashLength, Argon2SaltLengthPasswordPolicyProviderFactory.DEFAULT_SALT_LENGTH);
        }

        public Argon2Parameters(Argon2Variant argon2Variant, int version, int memory, int iterations, int parallelism, int hashLength, int saltLength) {
            this.argon2Variant = argon2Variant;
            this.version = version;
            this.memory = memory;
            this.iterations = iterations;
            this.parallelism = parallelism;
            this.hashLength = hashLength;
            this.saltLength = saltLength;
        }

        public Argon2Variant getArgon2Variant() {
            return argon2Variant;
        }

        public int getVersion() {
            return version;
        }

        public int getMemory() {
            return memory;
        }

        public int getIterations() {
            return iterations;
        }

        public int getParallelism() {
            return parallelism;
        }

        public int getHashLength() {
            return hashLength;
        }

        public int getSaltLength() {
            return saltLength;
        }
    }
}
