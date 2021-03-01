package org.pgpainless.key;

import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.util.selection.key.signature.SelectSignature;

public class KeyValidator {

    public PGPPublicKeyRing validatePublicKeyRing(PGPPublicKeyRing publicKeys) throws PGPException {
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        if (!isValidPrimaryKey(primaryKey, publicKeys)) {
            throw new PGPException("Primary key is not valid");
        }
        return publicKeys;
    }

    public static boolean isValidPrimaryKey(PGPPublicKey publicKey, PGPPublicKeyRing keyRing) {
        if (!publicKey.isMasterKey()) {
            return false;
        }

        if (keyRing.getPublicKey().getKeyID() != publicKey.getKeyID()) {
            return false;
        }

        Iterator<PGPSignature> signatures = publicKey.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
            switch (signatureType) {
                case KEY_REVOCATION:
                    if (SelectSignature.isValidKeyRevocationSignature(publicKey).accept(signature, keyRing)) {
                        return false;
                    }
            }
        }
        return true;
    }
}
