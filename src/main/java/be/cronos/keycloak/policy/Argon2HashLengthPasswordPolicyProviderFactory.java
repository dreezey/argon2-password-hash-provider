package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2HashLengthPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2HashLength";
    public static final int DEFAULT_HASH_LENGTH = 32;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Hash Length";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_HASH_LENGTH);
    }

}
