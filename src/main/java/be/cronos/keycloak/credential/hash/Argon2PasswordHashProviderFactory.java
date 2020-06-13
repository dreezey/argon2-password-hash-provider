package be.cronos.keycloak.credential.hash;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2PasswordHashProviderFactory implements PasswordHashProviderFactory {
    public static final String ID = "argon2";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new Argon2PasswordHashProvider(ID, session);
    }

    @Override
    public void init(Config.Scope config) {
        // noop
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // noop
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
        // noop
    }
}
