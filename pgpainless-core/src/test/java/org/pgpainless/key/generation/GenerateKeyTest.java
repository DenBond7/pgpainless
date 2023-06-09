/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.generation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.Passphrase;

public class GenerateKeyTest {

    private static final Logger LOGGER = Logger.getLogger(GenerateKeyTest.class.getName());

    @Test
    public void generateKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        String user = "default@denbond7.com";
        String oldPass = "android";
        String newPass = "My super strong password 2018";
        String newPassSecond = "My super strong passphrase 2019";

        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing(user, oldPass);
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        publicKeys.encode(armor);
        armor.close();
        String publicKey = bytes.toString();

        bytes = new ByteArrayOutputStream();
        armor = ArmoredOutputStreamFactory.get(bytes);
        secretKeys.encode(armor);
        armor.close();
        String privateKey = bytes.toString();

        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKeys);

        LOGGER.log(Level.INFO, String.format("Generated random fresh EC key ring.\n" +
                        "Creation date: %s\n" +
                        "User-ID: %s\n" +
                        "Fingerprint: %s\n" +
                        "Key-ID: %s\n" +
                        "%s\n" +
                        "%s\n", keyRingInfo.getCreationDate(), secretKeys.getPublicKey().getUserIDs().next(),
                new OpenPgpV4Fingerprint(publicKeys),
                publicKeys.getPublicKey().getKeyID(),
                publicKey, privateKey));

        PGPSecretKeyRing secretKeysMod = PGPainless.modifyKeyRing(secretKeys)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword(oldPass))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword(newPass))
                .done();

        bytes = new ByteArrayOutputStream();
        armor = ArmoredOutputStreamFactory.get(bytes);
        secretKeysMod.encode(armor);
        armor.close();
        System.out.println(bytes);

        PGPSecretKeyRing secretKeysModSecond = PGPainless.modifyKeyRing(secretKeys)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword(oldPass))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword(newPassSecond))
                .done();

        bytes = new ByteArrayOutputStream();
        armor = ArmoredOutputStreamFactory.get(bytes);
        secretKeysModSecond.encode(armor);
        armor.close();
        System.out.println(bytes);
    }
}
