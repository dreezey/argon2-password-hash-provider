package be.cronos.keycloak.policy;

import de.mkammerer.argon2.Argon2Constants;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2HashLengthPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2HashLength";

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
        return String.valueOf(Argon2Constants.DEFAULT_HASH_LENGTH);
    }

}
