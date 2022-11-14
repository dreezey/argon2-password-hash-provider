package be.cronos.keycloak.policy;

import be.cronos.keycloak.enums.Argon2Variant;
import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2VariantPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Variant";
    public static final String DEFAULT_ARGON2_VARIANT = Argon2Variant.ARGON2ID.getArgon2VariantStringRepr();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public Object parseConfig(String value) {
        Argon2Variant argon2Variant = Argon2Variant.parseVariant(value);
        if (argon2Variant == null) throw new PasswordPolicyConfigException("Invalid Argon2 variant, valid choices are: ARGON2i, ARGON2id or ARGON2d.");
        return argon2Variant.getArgon2VariantStringRepr();
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Variant";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_ARGON2_VARIANT);
    }


    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.STRING_CONFIG_TYPE;
    }
}
