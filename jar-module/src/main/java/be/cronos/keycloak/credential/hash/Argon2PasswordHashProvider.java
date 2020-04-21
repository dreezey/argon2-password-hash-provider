package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.policy.*;
import be.cronos.keycloak.utils.Argon2Helper;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2PasswordHashProvider implements PasswordHashProvider {

    private static final Logger LOG = Logger.getLogger(Argon2PasswordHashProvider.class);

    private final String providerId;

    private static final Argon2Types DEFAULT_ARGON_2_VARIANT = Argon2Types.ARGON2id;
    private static final int DEFAULT_ITERATIONS = 1;
    private KeycloakSession session;

    public Argon2PasswordHashProvider(String providerId, KeycloakSession session) {
        this.providerId = providerId;
        this.session = session;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        LOG.debugf("policyCheck()");
        int policyHashIterations = getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, DEFAULT_ITERATIONS);

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("encodedCredential()");

        // Get the Argon2 parameters, or default values
        int argon2Iterations = getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, DEFAULT_ITERATIONS);
        int parallelism = getDefaultValue(Argon2ParallelismPasswordPolicyProviderFactory.ID, 1);
        int memoryLimit = getDefaultValue(Argon2MemoryPasswordPolicyProviderFactory.ID, 65536);
        int hashLength = getDefaultValue(Argon2HashLengthPasswordPolicyProviderFactory.ID, Argon2Constants.DEFAULT_HASH_LENGTH);
        int saltLength = getDefaultValue(Argon2SaltLengthPasswordPolicyProviderFactory.ID, Argon2Constants.DEFAULT_SALT_LENGTH);
        Argon2Types argon2Variant = getDefaultValue(Argon2VariantPasswordPolicyProviderFactory.ID, DEFAULT_ARGON_2_VARIANT);
        int maxTime = getDefaultValue(Argon2MaxTimePasswordPolicyProviderFactory.ID, 1000);

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
        return "0123456789abcdef".getBytes();
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {

        LOG.debugf("verify()");

        return Argon2Helper.verifyPassword(rawPassword, credential);
    }

    @Override
    public void close() {
        // noop
    }
}
