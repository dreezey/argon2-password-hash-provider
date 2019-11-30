package be.cronos.keycloak.credential.hash;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class Argon2PasswordHashProviderFactory implements PasswordHashProviderFactory {
    private static final Logger LOG = Logger.getLogger(Argon2PasswordHashProviderFactory.class);

    public static final String ID = "argon2";

    public static final String HASHING_ALGORITHM = "argon2id";

    public static final int DEFAULT_ITERATIONS = 1;

    public static final int DEFAULT_MEMORY = 65536;

    public static final int DEFAULT_PARALLELISM = 1;

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
//        return new Pbkdf2PasswordHashProvider(ID, HASHING_ALGORITHM, 20000);
        LOG.errorf("Argon2 Factory");
        return new Argon2PasswordHashProvider(ID, HASHING_ALGORITHM, DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }
}
