package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
@Deprecated
public class Argon2MaxTimePasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2MaxTime";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Maximum Time (in ms)";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(1000);
    }

}
