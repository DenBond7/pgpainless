package org.pgpainless.key.generation.gen2;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;

public abstract class AbstractKeyBuilder<T> {

    protected PGPKeyPair keyPair;

    protected void setKeyPair(PGPKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    protected void setType(KeyType keyType, Date creationDate) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        setKeyPair(new KeyBuilder(keyType)
                .setKeyCreationTime(creationDate)
                .generate());
    }

    public abstract T rsa(RsaLength length, Date creationTime)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException;

    public abstract T ecdsa(EllipticCurve curve, Date creationTime)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException;

    public abstract T eddsa(EdDSACurve curve, Date creationTime)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException;
}
