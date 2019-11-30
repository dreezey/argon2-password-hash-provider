package be.cronos.keycloak.policy;

import be.cronos.keycloak.credential.hash.Argon2PasswordHashProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

public class Argon2ParallelismPasswordPolicyProviderFactory implements PasswordPolicyProvider, PasswordPolicyProviderFactory {
    private static final Logger LOG = Logger.getLogger(Argon2ParallelismPasswordPolicyProviderFactory.class);

    public static final String ID = "argon2Parallelism";

    @Override
    public Argon2ParallelismPasswordPolicyProviderFactory create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        LOG.debugf("Argon2ParallelismPasswordPolicyProviderFactory init()");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOG.debugf("Argon2ParallelismPasswordPolicyProviderFactory postInit()");
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        LOG.debugf("Argon2ParallelismPasswordPolicyProviderFactory validate()");
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        LOG.debugf("Argon2ParallelismPasswordPolicyProviderFactory validate()");
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, -1);
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Parallelism";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.INT_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(1);
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public void close() {
    }
}
