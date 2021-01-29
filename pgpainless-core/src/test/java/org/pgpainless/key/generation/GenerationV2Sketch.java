package org.pgpainless.key.generation;

import java.util.Date;

import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;

public class GenerationV2Sketch {

    public void test() throws Exception {
        PGPainless.generateKey()
                .withPrimaryKey() // <-- ChosePrimaryKey
                .rsa(RsaLength._4096) // <- PrimaryKey
                .withUsages(KeyFlag.SIGN_DATA | KeyFlag.ENCRYPT_STORAGE) // <- KeyAttributes
                .withExpiryDate(new Date()) // <- KeyAttributes
                .withPreferredHashAlgorithms(new HashAlgorithm[0]) // <- KeyAttributes
                .withPreferredSymmetricAlgorithms(new SymmetricKeyAlgorithm[0]) // <- KeyAttributes
                .withPreferredCompressionAlgorithms(new CompressionAlgorithm[0]) // <- KeyAttributes
                .withKeyExpirationDate(new Date()) // <- KeyAttributes
                .withFeatures(Feature.MODIFICATION_DETECTION) // <- KeyAttributes
                .finishPrimaryKey() // <- ChoseSubKeys()
                .withSubKey()
                .finishSubKeys()
        PGPainless.generateKey()
                .withPrimaryKey()
                .rsa(RsaLength._4096, new Date())
                .withAdditionalKeyFlags(KeyFlag.SIGN_DATA);
                .done()
                .withSigningSubKey()
                .ecdsa(EllipticCurve._P256, new Date())
                .done()
                .withEncryptionKey()
                .ecdh(EllipticCurve._P256, new Date())
                .done()
                .withPrimaryUserId();
    }
}
