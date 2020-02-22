package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.policy.*;
import be.cronos.keycloak.utils.Argon2Helper;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.SecureRandom;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
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
    private KeycloakSession session;

    public Argon2PasswordHashProvider(String providerId, Argon2Types defaultArgon2Variant, int defaultIterations, int defaultMemory, int defaultParallelism, int defaultHashLength, int defaultSaltLength, int defaultMaxTime, KeycloakSession session) {
        this.providerId = providerId;
        this.defaultArgon2Variant = defaultArgon2Variant;
        this.defaultIterations = defaultIterations;
        this.defaultMemory = defaultMemory;
        this.defaultParallelism = defaultParallelism;
        this.defaultHashLength = defaultHashLength;
        this.defaultSaltLength = defaultSaltLength;
        this.defaultMaxTime = defaultMaxTime;
        this.session = session;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        LOG.debugf("policyCheck()");
        int policyHashIterations = getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, defaultIterations);

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("encodedCredential()");

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

        // Keep track of hashing runtime
        long start = System.currentTimeMillis();
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, argon2Iterations, parallelism, memoryLimit, hashLength, saltLength);
        // Stop timing
        long end = System.currentTimeMillis();

        // Verify whether the hash time has not exceeded the configured value (or default value)
        LOG.debugf("Hashing runtime was %d milliseconds (%d seconds).", end-start, (end-start)/1000);
        if (end - start > maxTime) {
            LOG.warnf("Hash time exceeded configured maximum time: '%d ms', consider tuning the parameter 'Argon2 Iterations'.", maxTime);
        }

        // Salt doesn't matter here
        byte[] salt = getSalt();

        return PasswordCredentialModel.createFromValues(providerId, salt, argon2Iterations, hash);
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        LOG.debugf("getDefaultValue() providerId = '%s', defaultValue = '%s'", providerId, defaultValue);
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
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

        LOG.debugf("verify()");

        return Argon2Helper.verifyPassword(rawPassword, credential);
    }

    @Override
    public void close() {

    }
}
