// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.IOException
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPException

interface EncryptionBuilderInterface {

    /**
     * Create a [EncryptionStream] wrapping an [OutputStream]. Data that is piped through the
     * [EncryptionStream] will be encrypted and/or signed.
     *
     * @param outputStream output stream which receives the encrypted / signed data.
     * @return api handle
     */
    fun onOutputStream(outputStream: OutputStream): WithOptions

    /**
     * Create an [EncryptionStream] that discards the data after processing it. This is useful, e.g.
     * for generating detached signatures, where the resulting signature is retrieved from the
     * [EncryptionResult] once the operation is finished. In this case, the plaintext data does not
     * need to be retained.
     *
     * @return api handle
     */
    fun discardOutput(): WithOptions

    fun interface WithOptions {

        /**
         * Create an [EncryptionStream] with the given options (recipients, signers, algorithms...).
         *
         * @param options options
         * @return encryption stream
         * @throws PGPException if something goes wrong during encryption stream preparation
         * @throws IOException if something goes wrong during encryption stream preparation (writing
         *   headers)
         */
        @Throws(PGPException::class, IOException::class)
        fun withOptions(options: ProducerOptions): EncryptionStream
    }
}
