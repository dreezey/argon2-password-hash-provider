package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.policy.*;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.SecureRandom;

public class Argon2PasswordHashProvider implements PasswordHashProvider {

    private static final Logger LOG = Logger.getLogger(Argon2PasswordHashProvider.class);

    private final String providerId;

    private final Argon2Types defaultArgon2Variant;
    private final int defaultIterations;
    private final int defaultMemory;
    private final int defaultParallelism;
    private final int defaultHashLength;
    private final int defaultSaltLength;
    private final int defaultMaxTime;
    private PasswordPolicy passwordPolicy;

    public Argon2PasswordHashProvider(String providerId, Argon2Types defaultArgon2Variant, int defaultIterations, int defaultMemory, int defaultParallelism, int defaultHashLength, int defaultSaltLength, int defaultMaxTime) {
        this.providerId = providerId;
        this.defaultArgon2Variant = defaultArgon2Variant;
        this.defaultIterations = defaultIterations;
        this.defaultMemory = defaultMemory;
        this.defaultParallelism = defaultParallelism;
        this.passwordPolicy = null;
        this.defaultHashLength = defaultHashLength;
        this.defaultSaltLength = defaultSaltLength;
        this.defaultMaxTime = defaultMaxTime;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        int policyHashIterations = getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, defaultIterations);

        // This is hack and is not reliable, policyCheck() is only triggered on password CHANGE (not when setting a new password, or when the admin sets it)
        // However, due to the argon2.verify function, the variant is included, as well as iterations and memory limit
        this.passwordPolicy = policy;

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("Argon2 encodedCredential()");

        // Get the Argon2 parameters, or default values
        int argon2Iterations = getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, defaultIterations);
        int parallelism = getDefaultValue(Argon2ParallelismPasswordPolicyProviderFactory.ID, defaultParallelism);
        int memoryLimit = getDefaultValue(Argon2MemoryPasswordPolicyProviderFactory.ID, defaultMemory);
        int hashLength = getDefaultValue(Argon2HashLengthPasswordPolicyProviderFactory.ID, defaultHashLength);
        int saltLength = getDefaultValue(Argon2SaltLengthPasswordPolicyProviderFactory.ID, defaultSaltLength);
        Argon2Types argon2Variant = getDefaultValue(Argon2VariantPasswordPolicyProviderFactory.ID, defaultArgon2Variant);
        int maxTime = getDefaultValue(Argon2MaxTimePasswordPolicyProviderFactory.ID, defaultMaxTime);

        LOG.debugf("Using the following Argon2 settings:");
        LOG.debugf("\tArgon2 Variant: %s", argon2Variant);
        LOG.debugf("\tIterations: %d", argon2Iterations);
        LOG.debugf("\tParallelism: %d", parallelism);
        LOG.debugf("\tMemory limit: %d", memoryLimit);
        LOG.debugf("\tHash Length: %d", hashLength);
        LOG.debugf("\tSalt Length: %d", saltLength);
        LOG.debugf("\tMaximum time for hashing (in ms): %d", maxTime);

        Argon2 argon2 = Argon2Factory.createAdvanced(argon2Variant, defaultSaltLength, defaultHashLength);
        String hash;

        try {
            // Keep track of hashing runtime
            long start = System.currentTimeMillis();
            // Hash the password
            hash = argon2.hash(argon2Iterations, memoryLimit, parallelism, rawPassword);
            // Stop timing
            long end = System.currentTimeMillis();
            // Verify whether the hash time has not exceeded the configured value (or default value)
            LOG.debugf("Hashing runtime was %d milliseconds (%d seconds).", end-start, (end-start)/1000);
            if (end - start > maxTime) {
                LOG.warnf("Hash time exceeded configured maximum time: '%d ms', consider tuning the parameter 'Argon2 Iterations'.", maxTime);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Salt doesn't matter here
        byte[] salt = getSalt();

        return PasswordCredentialModel.createFromValues(providerId, salt, argon2Iterations, hash);
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        LOG.debugf("getDefaultValue() providerId = '%s', defaultValue = '%s'", providerId, defaultValue);
        T ret;
        try {
            ret = passwordPolicy.getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        LOG.debugf("getDefaultValue() return value = '%s'", ret);
        return ret;
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {

        LOG.debugf("Argon2 verify()");

        // Get the Argon2 variant of the credential, should be something like:
        // $argon2i$v=19$m=65535,t=30,p=4$JQUxqirAz7+Em0yM1ZiDFA$LhqtL0XPGESfeHb4lI2XnV4mSZacWGQWANKtvIVVpy4
        // however, the variant's case is not correct for the enum
        String storedVariant = credential.getPasswordSecretData().getValue().split("\\$")[1];
        Argon2Types storedArgon2Variant = null;
        try {
            for (Argon2Types argon2Type : Argon2Types.values()) {
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
            if (argon2.verify(credential.getPasswordSecretData().getValue(), rawPassword)) {
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

    @Override
    public void close() {

    }
}
