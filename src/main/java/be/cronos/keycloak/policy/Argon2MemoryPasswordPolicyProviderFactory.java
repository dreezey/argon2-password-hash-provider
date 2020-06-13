package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2MemoryPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Memory";
    public static final int DEFAULT_MEMORY = 65536;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Memory Usage (KB)";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_MEMORY);
    }

}
