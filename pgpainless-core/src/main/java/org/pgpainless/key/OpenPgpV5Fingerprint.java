// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 * This class represents a hex encoded, upper case OpenPGP v5 fingerprint.
 */
public class OpenPgpV5Fingerprint extends _64DigitFingerprint {

    /**
     * Create an {@link OpenPgpV5Fingerprint}.
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 64
     */
    public OpenPgpV5Fingerprint(@Nonnull String fingerprint) {
        super(fingerprint);
    }

    public OpenPgpV5Fingerprint(@Nonnull byte[] bytes) {
        super(bytes);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPPublicKey key) {
        super(key);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPSecretKey key) {
        this(key.getPublicKey());
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPPublicKeyRing ring) {
        super(ring);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPSecretKeyRing ring) {
        super(ring);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPKeyRing ring) {
        super(ring);
    }

    @Override
    public int getVersion() {
        return 5;
    }

}
