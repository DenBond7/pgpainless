package org.pgpainless.util.selection.key.signature;

import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;

public abstract class SelectSignature {

    private static final Logger LOGGER = Logger.getLogger(SelectSignature.class.getName());

    public abstract boolean accept(PGPSignature signature, PGPKeyRing keyRing);

    public static SelectSignature isValidSubkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {

                if (!isOfType(SignatureType.SUBKEY_BINDING).accept(signature, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != primaryKey.getKeyID()) {
                    return false;
                }

                boolean subkeyBindingSigValid;
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), primaryKey);
                    subkeyBindingSigValid = signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of subkey binding signature failed.", e);
                    return false;
                }

                if (!subkeyBindingSigValid) {
                    return false;
                }

                boolean isSigningKey = true;
                if (isSigningKey && !hasValidPrimaryKeyBindingSignatureSubpacket(subkey, primaryKey)
                        .accept(signature, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey binding signature on signing key does not carry primary key binding signature.");
                    return false;
                }
                return true;
            }
        };
    }

    public static SelectSignature isValidPrimaryKeyBindingSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {

                if (!isOfType(SignatureType.PRIMARYKEY_BINDING).accept(signature, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != subkey.getKeyID()) {
                    return false;
                }

                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), subkey);
                    return signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    return false;
                }
            }
        };
    }

    public static SelectSignature hasValidPrimaryKeyBindingSignatureSubpacket(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                PGPSignatureList signatureList;
                try {
                    signatureList = signature.getHashedSubPackets().getEmbeddedSignatures();
                } catch (PGPException e) {
                    return false;
                }

                for (PGPSignature embeddedSignature : signatureList) {
                    if (isValidPrimaryKeyBindingSignature(subkey, primaryKey).accept(embeddedSignature, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static SelectSignature isValidKeyRevocationSignature(PGPPublicKey key) {
        return and(
                isOfType(SignatureType.KEY_REVOCATION),
                isCreatedBy(key),
                isValidSignatureOnKey(key, key)
        );
    }

    public static SelectSignature isValidSubkeyRevocationSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return SelectSignature.and(
                isOfType(SignatureType.SUBKEY_REVOCATION),
                isCreatedBy(primaryKey),
                isValidSignatureOnKeys(primaryKey, subkey, primaryKey)
        );
    }

    public static SelectSignature isValidCertificationRevocationSignature(PGPPublicKey key, String userId) {
        return and(
                isCreatedBy(key),
                isOfType(SignatureType.CERTIFICATION_REVOCATION),
                isValidSignatureOnUserId(key, userId, key)
        );
    }

    public static SelectSignature isValidSignatureOnUserId(PGPPublicKey key, String userId, PGPPublicKey signingKey) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
                    return signature.verifyCertification(userId, key);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of signature on userID " + userId + " failed.", e);
                    return false;
                }
            }
        };
    }

    public static SelectSignature isValidSignatureOnKey(PGPPublicKey target, PGPPublicKey signer) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    return signature.verifyCertification(target);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Signature verification failed.", e);
                    return false;
                }
            }
        };
    }

    public static SelectSignature isValidSignatureOnKeys(PGPPublicKey primaryKey, PGPPublicKey subkey, PGPPublicKey signingKey) {
        if (signingKey.getKeyID() != primaryKey.getKeyID() && signingKey.getKeyID() != subkey.getKeyID()) {
            throw new IllegalArgumentException("Signing key MUST be either the primary or subkey.");
        }
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
                    return signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of " + SignatureType.valueOf(signature.getSignatureType()) + " signature failed.", e);
                    return false;
                }
            }
        };
    }

    public static SelectSignature wasCreatedBefore(Date date) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.getCreationTime().before(date);
            }
        };
    }

    public static SelectSignature wasCreatedAfter(Date date) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.getCreationTime().after(date);
            }
        };
    }

    public static SelectSignature isCertification() {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.isCertification();
            }
        };
    }

    public static SelectSignature isCreatedBy(PGPPublicKey publicKey) {
        return isCreatedBy(publicKey.getKeyID());
    }

    public static SelectSignature isCreatedBy(long keyId) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.getKeyID() == keyId;
            }
        };
    }

    public static SelectSignature isVersion(int version) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.getVersion() == version;
            }
        };
    }

    public static SelectSignature isOfType(SignatureType signatureType) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return signature.getSignatureType() == signatureType.getCode();
            }
        };
    }

    public static SelectSignature signatureUsesAnyAlgorithm(HashAlgorithm... hashAlgorithms) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                HashAlgorithm hashAlgorithm = HashAlgorithm.fromId(signature.getHashAlgorithm());
                for (HashAlgorithm allowed : hashAlgorithms) {
                    if (allowed == hashAlgorithm) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static SelectSignature hasKeyFlag(KeyFlag flag) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                int keyFlagMask = signature.getHashedSubPackets().getKeyFlags();
                return KeyFlag.hasKeyFlag(keyFlagMask, flag);
            }
        };
    }

    public static SelectSignature validSubKeyBindingSignature(PGPPublicKey publicKey, Date verificationDate) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                if (publicKey.isMasterKey()) {
                    // primary key cannot be subkey
                    return false;
                }

                if (signature.getSignatureType() != SignatureType.SUBKEY_BINDING.getCode()) {
                    // We are only considering subkey binding sigs
                    return false;
                }

                PGPPublicKey primaryKey = keyRing.getPublicKey();
                try {
                    boolean signatureVerifies = signature.verifyCertification(primaryKey, publicKey);
                    if (!signatureVerifies) {
                        return false;
                    }
                } catch (PGPException e) {
                    return false;
                }

                if (signature.getCreationTime().before(publicKey.getCreationTime())
                        || signature.getCreationTime().before(primaryKey.getCreationTime())) {
                    // Binding signature is older than primary or subkey
                    return false;
                }
                return true; // TODO
            }
        };
    }

    public static SelectSignature and(SelectSignature... selectors) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                for (SelectSignature selector : selectors) {
                    if (!selector.accept(signature, keyRing)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    public static SelectSignature or(SelectSignature... selectors) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                boolean accept = false;
                for (SelectSignature selector : selectors) {
                    accept |= selector.accept(signature, keyRing);
                }
                return accept;
            }
        };
    }

    public static SelectSignature not(SelectSignature selector) {
        return new SelectSignature() {
            @Override
            public boolean accept(PGPSignature signature, PGPKeyRing keyRing) {
                return !selector.accept(signature, keyRing);
            }
        };
    }
}
