package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;

public class PGPPublicKeyRingTest {

    /**
     * Learning test to see if BC also makes userids available on subkeys.
     * It does not.
     *
     * see also https://security.stackexchange.com/questions/92635/is-it-possible-to-assign-different-uids-to-subkeys-for-the-purpose-of-having-mul
     *
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     */
    @Test
    public void subkeysDoNotHaveUserIDsTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("primary@user.id");
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        for (PGPPublicKey subkey : publicKeys) {
            Iterator<String> userIds = subkey.getUserIDs();
            if (primaryKey == subkey) {
                assertEquals("primary@user.id", userIds.next());
                assertFalse(userIds.hasNext());
            } else {
                assertFalse(userIds.hasNext());
            }
        }
    }
}
