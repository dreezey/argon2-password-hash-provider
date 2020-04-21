package be.cronos.keycloak.policy;

import de.mkammerer.argon2.Argon2Factory;
import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2VariantPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Variant";
    private static final String DEFAULT_ARGON2_VARIANT = "ARGON2id";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public Object parseConfig(String value) {
        String argonVariant = value != null && value.length() > 0 ? value : DEFAULT_ARGON2_VARIANT;
        Argon2Factory.Argon2Types type;
        try {
            type = Argon2Factory.Argon2Types.valueOf(argonVariant);
        } catch (Exception e) {
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

}
