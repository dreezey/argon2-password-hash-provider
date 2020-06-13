package be.cronos.keycloak.policy;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.keycloak.policy.PasswordPolicyConfigException;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2VersionPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Version";
    public static final int DEFAULT_VERSION = Argon2Parameters.ARGON2_VERSION_13;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Version";
    }

    @Override
    public Object parseConfig(String value) {
        int valueAsInt = Integer.parseInt(value, 16);
        if (valueAsInt == Argon2Parameters.ARGON2_VERSION_10 || valueAsInt == Argon2Parameters.ARGON2_VERSION_13) {
            return valueAsInt;
        } else {
            throw new PasswordPolicyConfigException(String.format("Invalid Argon2 version, valid choices are: '%h' or '%h'.", Argon2Parameters.ARGON2_VERSION_10, Argon2Parameters.ARGON2_VERSION_13));
        }
    }

    @Override
    public String getDefaultConfigValue() {
        return String.format("%h", DEFAULT_VERSION);
    }
}
