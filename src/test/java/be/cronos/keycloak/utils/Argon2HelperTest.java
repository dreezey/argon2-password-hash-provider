package be.cronos.keycloak.utils;

import be.cronos.keycloak.credential.hash.Argon2PasswordHashProviderFactory;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2HelperTest {
    private static final String ALGORITHM = Argon2PasswordHashProviderFactory.ID;
    private static final int DEFAULT_ITERATIONS = 1;

    private static final int DEFAULT_MEMORY = 65536;

    private static final int DEFAULT_PARALLELISM = 1;

    private static final int DEFAULT_MAX_TIME = 1000;

    // region: argon2d
    @Test
    public void testArgon2dHashAndVerifySamePassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2d;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2dHashAndVerifyDifferentPassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2d;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assert.assertFalse(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2d";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedWrongHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "wrongpassword";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertFalse(verified);
    }

    // endregion: argon2d

    // region: argon2i
    @Test
    public void testArgon2iHashAndVerifySamePassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2i;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2iHashAndVerifyDifferentPassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2i;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assert.assertFalse(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2i";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedWrongHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertFalse(verified);
    }
    // endregion: argon2i

    // region: argon2id
    @Test
    public void testArgon2idHashAndVerifySamePassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2idHashAndVerifyDifferentPassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assert.assertFalse(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        String hash = "$argon2id$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertTrue(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedWrongHash() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertFalse(verified);
    }
    // endregion: argon2id

    // region: runtime exceptions
    @Test(expected = RuntimeException.class)
    public void testHashPasswordHashEmptyPassword() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = null;
        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    }

    @Test(expected = RuntimeException.class)
    public void testHashPasswordNoAlgorithm() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "novariantdefined";
        String hash = Argon2Helper.hashPassword(rawPassword, null, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    }

    // Keeps on processing
//    @Test(expected = RuntimeException.class)
//    public void testHashPasswordNegativeIterations() {
//        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
//        int iterations = -1;
//        String rawPassword = "novariantdefined";
//        String hash = Argon2Helper.hashPassword(rawPassword, argon2Variant, iterations, DEFAULT_PARALLELISM, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
//    }

    @Test(expected = RuntimeException.class)
    public void testHashPasswordNoParallelism() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "novariantdefined";
        String hash = Argon2Helper.hashPassword(rawPassword, null, iterations, 0, DEFAULT_MEMORY, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    }

    @Test(expected = RuntimeException.class)
    public void testHashPasswordNoMemory() {
        Argon2Factory.Argon2Types argon2Variant = Argon2Factory.Argon2Types.ARGON2id;
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "novariantdefined";
        String hash = Argon2Helper.hashPassword(rawPassword, null, iterations, DEFAULT_PARALLELISM, 0, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    }

    @Test(expected = RuntimeException.class)
    public void testVerifyPasswordInvalidAlgorithm() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        String hash = "$argon2idd$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
    }

    @Test(expected = RuntimeException.class)
    public void testVerifyPasswordNonsenseData() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        String hash = "nonsense";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
    }
    // endregion: runtime exceptions

    // region: wrong algorithm in hash

    @Test()
    public void testVerifyPasswordIncorrectAlgorithm() {
        int iterations = DEFAULT_ITERATIONS;
        String rawPassword = "testargon2id";
        // it should argon2id
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), iterations, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assert.assertFalse(verified);
    }

    // endregion: wrong algorithm in hash

}
