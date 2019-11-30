package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.policy.Argon2IterationsPasswordPolicyProviderFactory;
import be.cronos.keycloak.policy.Argon2MemoryPasswordPolicyProviderFactory;
import be.cronos.keycloak.policy.Argon2ParallelismPasswordPolicyProviderFactory;
import be.cronos.keycloak.policy.Argon2VariantPasswordPolicyProviderFactory;
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
    private PasswordPolicy passwordPolicy;

    public Argon2PasswordHashProvider(String providerId, Argon2Types defaultArgon2Variant, int defaultIterations, int defaultMemory, int defaultParallelism) {
        this.providerId = providerId;
        this.defaultArgon2Variant = defaultArgon2Variant;
        this.defaultIterations = defaultIterations;
        this.defaultMemory = defaultMemory;
        this.defaultParallelism = defaultParallelism;
        this.passwordPolicy = null;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        int policyHashIterations = policy.getHashIterations();
        if (policyHashIterations == -1) {
            policyHashIterations = defaultIterations;
        }
        // This is hack and is not reliable, policyCheck() is only triggered on password CHANGE (not when setting a new password, or when the admin sets it)
        // However, due to the argon2.verify function, the variant is included, as well as iterations and memory limit
        this.passwordPolicy = policy;

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("Argon2 encodedCredential()");
        LOG.debugf("Argon2 encodedCredential() -> rawPassword = %s", rawPassword);
        int argon2Iterations;
        int parallelism;
        int memoryLimit;
        Argon2Types argon2Variant;
        try {
            argon2Iterations = passwordPolicy.getPolicyConfig(Argon2IterationsPasswordPolicyProviderFactory.ID);
        } catch (Exception e) {
            argon2Iterations = defaultIterations;
        }
        try {
            parallelism = passwordPolicy.getPolicyConfig(Argon2ParallelismPasswordPolicyProviderFactory.ID);
        } catch (Exception e) {
            parallelism = defaultParallelism;
        }
        try {
            memoryLimit = passwordPolicy.getPolicyConfig(Argon2MemoryPasswordPolicyProviderFactory.ID);
        } catch (Exception e) {
            memoryLimit = defaultMemory;
        }
        try {
            argon2Variant = passwordPolicy.getPolicyConfig(Argon2VariantPasswordPolicyProviderFactory.ID);
        } catch (Exception e) {
            argon2Variant = defaultArgon2Variant;
        }

        LOG.debugf("Using the following Argon2 settings:\n");
        LOG.debugf("\tIterations: %d", argon2Iterations);
        LOG.debugf("\tParallelism: %d", parallelism);
        LOG.debugf("\tMemory limit: %d", memoryLimit);

        Argon2 argon2 = Argon2Factory.createAdvanced(argon2Variant);
        String hash;
        try {
            // Hash password
            hash = argon2.hash(argon2Iterations, memoryLimit, parallelism, rawPassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        LOG.debugf("Password hash: %s", hash);

        // Salt doesn't even matter
        byte[] salt = getSalt();
//        String encodedPassword = hashCredential(rawPassword, iterations);

        return PasswordCredentialModel.createFromValues(providerId, salt, argon2Iterations, hash);
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
        LOG.debugf("Argon2 verify() -> rawPassword = %s", rawPassword);

        // Get the configured variant
        Argon2Types configuredArgon2Variant;
        try {
            configuredArgon2Variant = passwordPolicy.getPolicyConfig(Argon2VariantPasswordPolicyProviderFactory.ID);
        } catch (Exception e) {
            configuredArgon2Variant = defaultArgon2Variant;
        }

        // Get the Argon2 variant of the credential, should be something like:
        // $argon2i$v=19$m=65535,t=30,p=4$JQUxqirAz7+Em0yM1ZiDFA$LhqtL0XPGESfeHb4lI2XnV4mSZacWGQWANKtvIVVpy4
        // however, the variant's case is not correct for the enum

        String storedVariant = credential.getPasswordSecretData().getValue().split("\\$")[1];
        LOG.debugf("Stored variant found: %s", storedVariant);
        Argon2Types storedArgon2Variant = null;
        try {
            storedArgon2Variant = Argon2Types.valueOf(storedVariant);
        } catch (Exception e) {
            try {
                for (Argon2Types argon2Type : Argon2Types.values()) {
                    if (argon2Type.toString().equalsIgnoreCase(storedVariant)) {
                        storedArgon2Variant = argon2Type;
                    }
                }
                if (storedArgon2Variant == null) throw new Exception("Unknown stored Argon2 variant");
            } catch (Exception e1) {
                throw new RuntimeException("Unknown stored Argon2 variant, is someone spoofing?");
            }
        }

        // Now make sure to select the correct variant for the Argon2Factory
        Argon2 argon2;
        if (configuredArgon2Variant == storedArgon2Variant) {
            LOG.debugf("Stored Argon2 variant is same as configured Argon2 variant");
            argon2 = Argon2Factory.createAdvanced(configuredArgon2Variant);
        } else {
            LOG.debugf("Stored Argon2 variant is different than configured Argon2 variant, using stored variant to prevent lockout.");
            argon2 = Argon2Factory.createAdvanced(storedArgon2Variant);
        }

        boolean samePassword = false;
        try {
            LOG.debugf("The stored credential: '%s'", credential.getPasswordSecretData().getValue());
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
