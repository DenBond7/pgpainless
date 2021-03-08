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
package org.pgpainless.encryption_signing;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.SecretKeyNotFoundException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Passphrase;

public interface EncryptionBuilderInterface {

    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data that
     * shall be encrypted and or signed.
     *
     * @param outputStream output stream of the plain data.
     * @return api handle
     */
    ToRecipients onOutputStream(@Nonnull OutputStream outputStream);

    interface ToRecipients extends AdditionalRecipient {

        /**
         * Instruct the {@link EncryptionStream} to not encrypt any data.
         *
         * @return api handle
         */
        DetachedSign doNotEncrypt();
    }

    interface AdditionalRecipient {

        AndToRecipient toKey(PGPPublicKeyRing publicKey);

        AndToRecipient toRecipient(String userId, PGPPublicKeyRing publicKey);

        AndToRecipient toRecipient(String userId, PGPPublicKeyRingCollection publicKeyRingCollection);

        /**
         * Encrypt to a symmetric passphrase.
         *
         * @param passphrase passphrase
         * @return api handle
         */
        AndToRecipient toPassphrase(Passphrase passphrase);
    }

    interface AndToRecipient {
        AdditionalRecipient and();

        DetachedSign finishRecipients();
    }

    interface DetachedSign extends SignWith {

        SignWith createInlineSignature();

        /**
         * Instruct the {@link EncryptionStream} to generate detached signatures instead of One-Pass-Signatures.
         * Those can be retrieved later via {@link OpenPgpMetadata#getSignatures()}.
         *
         * @return api handle
         */
        SignWith createDetachedSignature();

        /**
         * Do not sign the plain data at all.
         *
         * @return api handle
         */
        Armor doNotSign();

    }

    interface SignWith {


        /**
         * Pass in a list of secret keys used for signing, along with a {@link SecretKeyRingProtector} used to unlock
         * the secret keys.
         *
         * @param userId userId of the signer
         * @param decryptor {@link SecretKeyRingProtector} used to unlock the secret keys
         * @param secretKey secret key ring
         * @return api handle
         */
        AndSignWith signWith(@Nonnull String userId, @Nonnull PGPSecretKeyRing secretKey, SecretKeyRingProtector decryptor);

        Armor signBinaryDocument();

        Armor signCanonicalText();
    }

    interface AndSignWith {
        SignWith and();
    }

    interface Armor {

        /**
         * Wrap the encrypted/signed output in an ASCII armor.
         * This can come in handy for sending the encrypted message via eg. email.
         *
         * @return encryption stream
         * @throws IOException in case some I/O error occurs
         * @throws PGPException in case of some malformed pgp data
         */
        EncryptionStream asciiArmor() throws IOException, PGPException;

        /**
         * Do not wrap the output in an ASCII armor.
         *
         * @return encryption stream
         * @throws IOException in case some I/O error occurs
         * @throws PGPException in case of some malformed pgp data
         */
        EncryptionStream noArmor() throws IOException, PGPException;

    }

    class Options {
        HashAlgorithm hashAlgorithm;
        SymmetricKeyAlgorithm sessionKeyAlgorithm;
        CompressionAlgorithm compressionAlgorithm;
    }

}
