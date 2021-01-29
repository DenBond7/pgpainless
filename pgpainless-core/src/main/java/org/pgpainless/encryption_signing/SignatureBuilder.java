package org.pgpainless.encryption_signing;

import java.util.Date;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;

public class SignatureBuilder {

    private SignatureType type;
    private Date creationTime = new Date();
    private HashAlgorithm hashAlgorithm = PGPainless.getPolicy().getDefaultSignatureHashAlgorithm();

    private SignatureBuilder() {

    }

    public static SignatureBuilder getInstance(SignatureType type) {
        SignatureBuilder builder = new SignatureBuilder();
        builder.type = type;
        return builder;
    }

    public SignatureBuilder withCreationTime(Date creationTime) {
        this.creationTime = creationTime;
        return this;
    }

    public SignatureBuilder usingHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    public PGPSignature build() {
        return null;
    }
}
