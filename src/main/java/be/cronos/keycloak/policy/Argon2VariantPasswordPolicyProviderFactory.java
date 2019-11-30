package be.cronos.keycloak.policy;

import de.mkammerer.argon2.Argon2Factory;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

public class Argon2VariantPasswordPolicyProviderFactory implements PasswordPolicyProvider, PasswordPolicyProviderFactory {
    public static final String ID = "argon2Variant";
    private final String DEFAULT_ARGON2_VARIANT = "ARGON2id";

    @Override
    public Argon2VariantPasswordPolicyProviderFactory create(KeycloakSession session) {
        return this;
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
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        String argonVariant = value != null && value.length() > 0 ? value : DEFAULT_ARGON2_VARIANT;
        Argon2Factory.Argon2Types type;
        try {
            type = Argon2Factory.Argon2Types.valueOf(argonVariant);
        } catch (Exception e) {
            type = Argon2Factory.Argon2Types.valueOf(DEFAULT_ARGON2_VARIANT);
            throw new PasswordPolicyConfigException("Invalid Argon2 variant, valid choices are: ARGON2i, ARGON2id or ARGON2d.");
        }
        return type;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Variant";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.STRING_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return DEFAULT_ARGON2_VARIANT;
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public void close() {
    }
}
