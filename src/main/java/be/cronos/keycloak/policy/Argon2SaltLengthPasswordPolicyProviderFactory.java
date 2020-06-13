package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2SaltLengthPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2SaltLength";
    public static final int DEFAULT_SALT_LENGTH = 16;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Salt Length";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_SALT_LENGTH);
    }

}
