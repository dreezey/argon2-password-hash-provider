package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.enums.Argon2Variant;
import be.cronos.keycloak.policy.*;
import be.cronos.keycloak.utils.Argon2EncodingUtils;
import be.cronos.keycloak.utils.Argon2Helper;
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
    private final KeycloakSession session;

    public Argon2PasswordHashProvider(String providerId, KeycloakSession session) {
        this.providerId = providerId;
        this.session = session;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        LOG.debugf("> policyCheck()");
        // Get the credential's Argon2 parameters
        Argon2EncodingUtils.Argon2Parameters storedArgon2Parameters = Argon2EncodingUtils.extractArgon2ParametersFromEncodedPassword(credential.getPasswordSecretData().getValue());
        // Get the configured Argon2 parameters
        Argon2EncodingUtils.Argon2Parameters configuredArgon2Parameters = getConfiguredArgon2Parameters();

        // Perform a comparison on whether a re-hash is needed
        boolean meetsRealmPolicy = providerId.equals(credential.getPasswordCredentialData().getAlgorithm())
                && storedArgon2Parameters.getArgon2Variant().getArgon2BouncyCastle() == configuredArgon2Parameters.getArgon2Variant().getArgon2BouncyCastle()
                && storedArgon2Parameters.getVersion() == configuredArgon2Parameters.getVersion()
                && storedArgon2Parameters.getMemory() == configuredArgon2Parameters.getMemory()
                && storedArgon2Parameters.getIterations() == configuredArgon2Parameters.getIterations()
                && storedArgon2Parameters.getParallelism() == configuredArgon2Parameters.getParallelism();

        LOG.debugf("< policyCheck() -> Stored password meets Realm Password Policy = '%s'.", String.valueOf(meetsRealmPolicy));
        return meetsRealmPolicy;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("> encodedCredential()");

        // Get the configured Argon2 parameters, or default values
        Argon2EncodingUtils.Argon2Parameters configuredArgon2Parameters = getConfiguredArgon2Parameters();

        // Generate a salt
        byte[] salt = Argon2Helper.getSalt(configuredArgon2Parameters.getSaltLength());

        // Retrieve an encoded Argon2 password hash
        String hash = Argon2Helper.hashPassword(
                rawPassword,
                salt,
                configuredArgon2Parameters.getArgon2Variant(),
                configuredArgon2Parameters.getVersion(),
                configuredArgon2Parameters.getIterations(),
                configuredArgon2Parameters.getParallelism(),
                configuredArgon2Parameters.getMemory(),
                configuredArgon2Parameters.getHashLength()
        );

        LOG.debugf("< encodedCredential()");
        return PasswordCredentialModel.createFromValues(providerId, salt, configuredArgon2Parameters.getIterations(), hash);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        LOG.debugf("> verify()");

        // Verify whether the incoming password matches the stored password
        boolean passwordsMatch = Argon2Helper.verifyPassword(rawPassword, credential);

        LOG.debugf("< verify()");
        return passwordsMatch;
    }

    @Override
    public void close() {
        // noop
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        return ret;
    }

    private Argon2EncodingUtils.Argon2Parameters getConfiguredArgon2Parameters() {
        return new Argon2EncodingUtils.Argon2Parameters(
                Argon2Variant.parseVariant(getDefaultValue(Argon2VariantPasswordPolicyProviderFactory.ID, Argon2VariantPasswordPolicyProviderFactory.DEFAULT_ARGON2_VARIANT)),
                getDefaultValue(Argon2VersionPasswordPolicyProviderFactory.ID, Argon2VersionPasswordPolicyProviderFactory.DEFAULT_VERSION),
                getDefaultValue(Argon2MemoryPasswordPolicyProviderFactory.ID, Argon2MemoryPasswordPolicyProviderFactory.DEFAULT_MEMORY),
                getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, Argon2IterationsPasswordPolicyProviderFactory.DEFAULT_ITERATIONS),
                getDefaultValue(Argon2ParallelismPasswordPolicyProviderFactory.ID, Argon2ParallelismPasswordPolicyProviderFactory.DEFAULT_PARALLELISM),
                getDefaultValue(Argon2HashLengthPasswordPolicyProviderFactory.ID, Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH),
                getDefaultValue(Argon2SaltLengthPasswordPolicyProviderFactory.ID, Argon2SaltLengthPasswordPolicyProviderFactory.DEFAULT_SALT_LENGTH)
        );
    }
}
