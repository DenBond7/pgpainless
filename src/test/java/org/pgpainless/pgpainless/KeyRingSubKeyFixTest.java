/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.Test;
import org.pgpainless.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.pgpainless.util.KeyRingSubKeyFix;

public class KeyRingSubKeyFixTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void test()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing ring = PGPainless.generateKeyRing().simpleEcKeyRing("hallo@welt.de");
        PGPSecretKeyRing secretKeys = ring.getSecretKeys();
        PGPPublicKeyRing publicKeys = ring.getPublicKeys();

        PGPSecretKeyRing fixed = KeyRingSubKeyFix.repairSubkeyPackets(secretKeys, null, null);
        PGPPublicKeyRing fixedPub = publicKeyRing(fixed);

        assertTrue(Arrays.equals(publicKeys.getEncoded(), fixedPub.getEncoded()));
    }

    private PGPPublicKeyRing publicKeyRing(PGPSecretKeyRing secretKeys) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);
        for (PGPSecretKey s : secretKeys) {
            PGPPublicKey p = s.getPublicKey();
            if (p != null) {
                p.encode(buffer);
            }
        }

        return new PGPPublicKeyRing(buffer.toByteArray(), new BcKeyFingerprintCalculator());
    }
}