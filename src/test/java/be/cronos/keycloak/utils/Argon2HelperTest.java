package be.cronos.keycloak.utils;

import java.util.Base64;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.keycloak.models.credential.PasswordCredentialModel;

import be.cronos.keycloak.credential.hash.Argon2PasswordHashProviderFactory;
import be.cronos.keycloak.enums.Argon2Variant;
import be.cronos.keycloak.policy.Argon2HashLengthPasswordPolicyProviderFactory;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2HelperTest {

    private static final String ALGORITHM = Argon2PasswordHashProviderFactory.ID;
    private static final int DEFAULT_ITERATIONS = 1;

    private static final int DEFAULT_MEMORY = 65536;

    private static final int DEFAULT_PARALLELISM = 1;

    private static byte[] salt;

    @BeforeEach
    public void generateSalt() {
        salt = Argon2Helper.getSalt(16);
    }

    // region: argon2d
    @Test
    public void testArgon2dHashAndVerifySamePassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2D;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            iterations,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2dHashAndVerifyDifferentPassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2D;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            iterations,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedHash() {
        String rawPassword = "testargon2d";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("v3evK1HhIHKHRnRNWqEfZA"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2d";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    // endregion: argon2d

    // region: argon2i
    @Test
    public void testArgon2iHashAndVerifySamePassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2I;
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2iHashAndVerifyDifferentPassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2I;
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedHash() {
        String rawPassword = "testargon2i";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2i";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }
    // endregion: argon2i

    // region: argon2id
    @Test
    public void testArgon2idHashAndVerifySamePassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2idHashAndVerifyDifferentPassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedHash() {
        String rawPassword = "testargon2id";
        String hash = "$argon2id$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("zGFM95kyhWZyZv1Hhvjuog"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2id";
        String hash = "$argon2id$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }
    // endregion: argon2id

    // region: runtime exceptions
    @Test
    public void testHashPasswordHashEmptyPassword() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        Assertions.assertThrows(
            RuntimeException.class,
            () -> Argon2Helper.hashPassword(
                null,
                salt,
                argon2Variant,
                Argon2Parameters.ARGON2_VERSION_13,
                DEFAULT_ITERATIONS,
                DEFAULT_PARALLELISM,
                DEFAULT_MEMORY,
                Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
            )
        );
    }

    @Test
    public void testHashPasswordNoAlgorithm() {
        String rawPassword = "novariantdefined";
        String tamperedHash = "$$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_ITERATIONS, tamperedHash);
        passwordCredentialModel.setSecretData(tamperedHash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }

    @Test
    public void testHashPasswordNegativeIterations() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        int iterations = -1;
        String rawPassword = "novariantdefined";
        Executable exec = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            iterations,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, exec);
    }

    @Test
    public void testHashPasswordInvalidVersion() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        int version = 0x16;
        String rawPassword = "invalidversion";
        Executable call = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            version,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, call);
    }

    @Test
    public void testHashPasswordNoParallelism() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        int parallelism = 0;
        String rawPassword = "novariantdefined";
        Executable call = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            parallelism,
            DEFAULT_MEMORY,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, call);
    }

    @Test
    public void testHashPasswordNoMemory() {
        Argon2Variant argon2Variant = Argon2Variant.ARGON2ID;
        int memory = 0;
        String rawPassword = "novariantdefined";
        Executable call = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            argon2Variant,
            Argon2Parameters.ARGON2_VERSION_13,
            DEFAULT_ITERATIONS,
            DEFAULT_PARALLELISM,
            memory,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, call);
    }

    @Test
    public void testVerifyPasswordInvalidAlgorithm() {
        String rawPassword = "testargon2id";
        String hash = "$argon2idd$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }

    @Test
    public void testVerifyPasswordNonsenseData() {
        String rawPassword = "testargon2id";
        String hash = "nonsense";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_ITERATIONS, hash);
        passwordCredentialModel.setSecretData(hash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }
    // endregion: runtime exceptions

    // region: wrong algorithm in hash

    @Test
    public void testVerifyPasswordIncorrectAlgorithm() {
        String rawPassword = "testargon2id";
        // it should argon2id
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("zGFM95kyhWZyZv1Hhvjuog"),
            DEFAULT_ITERATIONS,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    // endregion: wrong algorithm in hash

}
