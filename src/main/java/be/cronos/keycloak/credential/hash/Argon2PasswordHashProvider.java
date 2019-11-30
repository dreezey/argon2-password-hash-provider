package be.cronos.keycloak.credential.hash;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.SecureRandom;

public class Argon2PasswordHashProvider implements PasswordHashProvider {

    private static final Logger LOG = Logger.getLogger(Argon2PasswordHashProvider.class);

    private final String providerId;

//    private final String argon2Algorithm;
    private final int defaultIterations;
    private final int defaultMemory;
    private final int defaultParallelism;

    public Argon2PasswordHashProvider(String providerId, String argon2Algorithm, int defaultIterations, int defaultMemory, int defaultParallelism) {
        this.providerId = providerId;
//        this.argon2Algorithm = argon2Algorithm;
        this.defaultIterations = defaultIterations;
        this.defaultMemory = defaultMemory;
        this.defaultParallelism = defaultParallelism;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        LOG.errorf("Argon2 policyCheck()");
        int policyHashIterations = policy.getHashIterations();
        if (policyHashIterations == -1) {
            policyHashIterations = defaultIterations;
        }

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.errorf("Argon2 encodedCredential()");
        if (iterations == -1) {
            iterations = defaultIterations;
        }

        Argon2 argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
        String hash;
        try {
            // Hash password
            hash = argon2.hash(iterations, defaultMemory, defaultParallelism, rawPassword);
        } finally {
            // do wipe
        }
        LOG.debugf("Hash is %s ", hash);
        LOG.debugf("argon2 verify:");
        try {
            LOG.debugf("argon2 verify matches = %s", argon2.verify(hash, rawPassword));
        } finally {
            // do something
        }

        byte[] salt = getSalt();
//        String encodedPassword = hashCredential(rawPassword, iterations);

        return PasswordCredentialModel.createFromValues(providerId, salt, iterations, hash);
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    private String hashCredential(String rawPassword, int iterations) {
        Argon2 argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
        String hash;
        try {
            // Hash password
            hash = argon2.hash(iterations, defaultMemory, defaultParallelism, rawPassword);
        } finally {
            // do wipe
        }
        LOG.debugf("Hash is %s ", hash);
        return hash;
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        LOG.debugf("Argon2 verify()");
        Argon2 argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
        try {
            if (argon2.verify(credential.getPasswordSecretData().getValue(), rawPassword)) {
                LOG.debugf("Passwords match!!");
                return true;
            }
        } finally {
            LOG.debugf("Passwords don't match!!");
        }
        return false;
//        return credential.getPasswordSecretData().getValue().equals(encodedCredential(rawPassword, credential.getPasswordCredentialData().getHashIterations()));
    }

    @Override
    public void close() {

    }
}
