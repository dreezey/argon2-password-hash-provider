package be.cronos.keycloak.enums;

import org.bouncycastle.crypto.params.Argon2Parameters;

import java.util.Arrays;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public enum Argon2Variant {
    ARGON2I("argon2i", Argon2Parameters.ARGON2_i),
    ARGON2D("argon2d", Argon2Parameters.ARGON2_d),
    ARGON2ID("argon2id", Argon2Parameters.ARGON2_id);

    private final String argon2VariantStringRepr;
    private final int argon2BouncyCastle;

    Argon2Variant(String argon2VariantStringRepr, int argon2BouncyCastle) {
        this.argon2VariantStringRepr = argon2VariantStringRepr;
        this.argon2BouncyCastle = argon2BouncyCastle;
    }

    public String getArgon2VariantStringRepr() {
        return argon2VariantStringRepr;
    }

    public int getArgon2BouncyCastle() {
        return argon2BouncyCastle;
    }

    public static boolean isValidVariant(String variant) {
        return Arrays
                .stream(Argon2Variant.values())
                .anyMatch(v -> v.argon2VariantStringRepr.equalsIgnoreCase(variant));
    }

    public static Argon2Variant parseVariant(String variant) {
        if (isValidVariant(variant)) {
            return Argon2Variant.valueOf(variant.toUpperCase());
        }
        return null;
    }

}
