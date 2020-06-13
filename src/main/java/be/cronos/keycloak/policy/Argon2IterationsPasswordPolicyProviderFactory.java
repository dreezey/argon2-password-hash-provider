package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2IterationsPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Iterations";
    public static final int DEFAULT_ITERATIONS = 1;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Iterations";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_ITERATIONS);
    }
}
