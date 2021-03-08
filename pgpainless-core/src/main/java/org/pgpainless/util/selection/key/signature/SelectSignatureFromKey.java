/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.util.selection.key.signature;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.util.SignatureUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.selection.signature.SignatureFilter;

public abstract class SelectSignatureFromKey {

    private static final Logger LOGGER = Logger.getLogger(SelectSignatureFromKey.class.getName());

    public static SelectSignatureFromKey isValidAt(Date validationDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                Date expirationDate = SignatureUtils.getSignatureExpirationDate(signature);
                return signature.getCreationTime().before(validationDate) && (expirationDate == null || expirationDate.after(validationDate));
            }
        };
    }

    public abstract boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing);

    public static SelectSignatureFromKey isValid() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return or(
                        // Key Revocation Sig
                        and(
                                isOfType(SignatureType.KEY_REVOCATION),
                                isValidKeyRevocationSignature(key)
                        ),
                        // Subkey Revocation Sig
                        and(
                                isOfType(SignatureType.SUBKEY_REVOCATION),
                                isValidSubkeyRevocationSignature()
                        ),
                        and(
                                isOfType(SignatureType.CERTIFICATION_REVOCATION)
                                // isValidCertificationRevocationSignature()
                        )
                ).accept(signature, key, keyRing);
            }
        };
    }

    public List<PGPSignature> select(List<PGPSignature> signatures, PGPPublicKey key, PGPKeyRing keyRing) {
        List<PGPSignature> selected = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            if (accept(signature, key, keyRing)) {
                selected.add(signature);
            }
        }
        return selected;
    }

    public static SelectSignatureFromKey isValidSubkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {

                if (!isOfType(SignatureType.SUBKEY_BINDING).accept(signature, key, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != primaryKey.getKeyID()) {
                    return false;
                }

                if (!isSigNotExpired().accept(signature, key, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey binding signature expired");
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

                boolean isSigningKey = PublicKeyAlgorithm.fromId(subkey.getAlgorithm()).isSigningCapable();
                if (isSigningKey && !hasValidPrimaryKeyBindingSignatureSubpacket(subkey, primaryKey)
                        .accept(signature, subkey, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey binding signature on signing key does not carry valid primary key binding signature.");
                    return false;
                }
                return true;
            }
        };
    }

    public static SelectSignatureFromKey isValidPrimaryKeyBindingSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {

                if (!isOfType(SignatureType.PRIMARYKEY_BINDING).accept(signature, key, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != subkey.getKeyID()) {
                    return false;
                }

                if (!isSigNotExpired().accept(signature, primaryKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Primary key binding signature expired.");
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

    public static SelectSignatureFromKey hasValidPrimaryKeyBindingSignatureSubpacket(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                PGPSignatureList signatureList;
                try {
                    signatureList = signature.getHashedSubPackets().getEmbeddedSignatures();
                } catch (PGPException e) {
                    return false;
                }

                for (PGPSignature embeddedSignature : signatureList) {
                    if (isValidPrimaryKeyBindingSignature(subkey, primaryKey).accept(embeddedSignature, subkey, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static SelectSignatureFromKey isValidKeyRevocationSignature(PGPPublicKey key) {
        return and(
                isOfType(SignatureType.KEY_REVOCATION),
                isCreatedBy(key),
                isWellFormed(),
                isSigNotExpired(),
                doesNotPredateKeyCreationDate(key),
                isVerifyingSignatureOnKey(key, key)
        );
    }

    public static SelectSignatureFromKey isValidSubkeyRevocationSignature() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return isValidSubkeyRevocationSignature(key, keyRing.getPublicKey())
                        .accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey isValidSubkeyRevocationSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return SelectSignatureFromKey.and(
                isOfType(SignatureType.SUBKEY_REVOCATION),
                isCreatedBy(primaryKey),
                isVerifyingSignatureOnKeys(primaryKey, subkey, primaryKey)
        );
    }

    public static SelectSignatureFromKey isValidCertificationRevocationSignature(String userId) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return isValidCertificationRevocationSignature(key, userId)
                        .accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey isValidCertificationRevocationSignature(PGPPublicKey revoker, String userId) {
        return and(
                isCreatedBy(revoker),
                isOfType(SignatureType.CERTIFICATION_REVOCATION),
                isValidSignatureOnUserId(userId, revoker)
        );
    }

    public static SelectSignatureFromKey isValidSignatureOnUserId(String userId, PGPPublicKey signingKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
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

    public static SelectSignatureFromKey isVerifyingSignatureOnKey(PGPPublicKey target, PGPPublicKey signer) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
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

    public static SelectSignatureFromKey isVerifyingSignatureOnKeys(PGPPublicKey primaryKey, PGPPublicKey subkey, PGPPublicKey signingKey) {
        if (signingKey.getKeyID() != primaryKey.getKeyID() && signingKey.getKeyID() != subkey.getKeyID()) {
            throw new IllegalArgumentException("Signing key MUST be either the primary or subkey.");
        }
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
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

    public static SelectSignatureFromKey wasCreatedBefore(Date date) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getCreationTime().before(date);
            }
        };
    }

    public static SelectSignatureFromKey wasCreatedAfter(Date date) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getCreationTime().after(date);
            }
        };
    }

    public static SelectSignatureFromKey wasCreatedInTimeframe(Date start, Date end) {
        return and(
                wasCreatedBefore(end),
                wasCreatedAfter(start)
        );
    }

    public static SelectSignatureFromKey isCertification() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.isCertification();
            }
        };
    }

    public static SelectSignatureFromKey isWellFormed() {
        return and(
                hasCreationTimeSubpacket(),
                doesNotPredateKeyCreationDate()
        );
    }

    public static SelectSignatureFromKey hasCreationTimeSubpacket() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getHashedSubPackets().getSignatureCreationTime() != null;
            }
        };
    }

    public static SelectSignatureFromKey isCreatedBy(PGPPublicKey publicKey) {
        return isCreatedBy(publicKey.getKeyID());
    }

    public static SelectSignatureFromKey isCreatedBy(long keyId) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getKeyID() == keyId;
            }
        };
    }

    public static SelectSignatureFromKey isCreatorInKeyRing() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return keyRing.getPublicKey(signature.getKeyID()) != null;
            }
        };
    }

    public static SelectSignatureFromKey isCreatorInKeyRing(PGPKeyRing myKeyRing) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return myKeyRing.getPublicKey(signature.getKeyID()) != null;
            }
        };
    }

    public static SelectSignatureFromKey isSigNotExpired() {
        return isSigNotExpired(new Date());
    }

    public static SelectSignatureFromKey isSigNotExpired(Date comparisonDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !SignatureUtils.isSignatureExpired(signature, comparisonDate);
            }
        };
    }

    public static SelectSignatureFromKey doesNotPredateKeyCreationDate() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                PGPPublicKey creator = keyRing.getPublicKey(signature.getKeyID());
                if (creator == null) {
                    return false;
                }
                return doesNotPredateKeyCreationDate(creator).accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey doesNotPredateKeyCreationDate(PGPPublicKey creator) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getCreationTime().after(creator.getCreationTime());
            }
        };
    }

    public static SelectSignatureFromKey isVersion(int version) {
        return adapter(SignatureFilter.isOfVersion(version));
    }

    public static SelectSignatureFromKey isOfType(SignatureType signatureType) {
        return adapter(SignatureFilter.isOfType(signatureType));
    }

    public static SelectSignatureFromKey signatureUsesAnyAlgorithm(HashAlgorithm... hashAlgorithms) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
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

    public static SelectSignatureFromKey policyAllowsSignatureHashAlgorithm() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
                Policy.HashAlgorithmPolicy hashAlgorithmPolicy;
                switch (signatureType) {
                    case BINARY_DOCUMENT:
                    case CANONICAL_TEXT_DOCUMENT:
                    case STANDALONE:
                    case GENERIC_CERTIFICATION:
                    case NO_CERTIFICATION:
                    case CASUAL_CERTIFICATION:
                    case POSITIVE_CERTIFICATION:
                    case SUBKEY_BINDING:
                    case PRIMARYKEY_BINDING:
                    case DIRECT_KEY:
                    case TIMESTAMP:
                    case THIRD_PARTY_CONFIRMATION:
                        hashAlgorithmPolicy = PGPainless.getPolicy().getSignatureHashAlgorithmPolicy();
                        break;
                    case KEY_REVOCATION:
                    case SUBKEY_REVOCATION:
                    case CERTIFICATION_REVOCATION:
                        hashAlgorithmPolicy = PGPainless.getPolicy().getRevocationSignatureHashAlgorithmPolicy();
                        break;
                    default:
                        throw new IllegalArgumentException("Signature has invalid signature type: " + signature.getSignatureType());
                }
                return policyAllowsSignatureHashAlgorithm(hashAlgorithmPolicy).accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey policyAllowsSignatureHashAlgorithm(Policy.HashAlgorithmPolicy hashAlgorithmPolicy) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return hashAlgorithmPolicy.isAcceptable(signature.getHashAlgorithm());
            }
        };
    }

    public static SelectSignatureFromKey hasKeyFlag(KeyFlag flag) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                int keyFlagMask = signature.getHashedSubPackets().getKeyFlags();
                return KeyFlag.hasKeyFlag(keyFlagMask, flag);
            }
        };
    }

    public static SelectSignatureFromKey validSubKeyBindingSignature(PGPPublicKey publicKey) {
        return validSubKeyBindingSignature(publicKey, new Date());
    }

    public static SelectSignatureFromKey validSubKeyBindingSignature(PGPPublicKey publicKey, Date verificationDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
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

    public static SelectSignatureFromKey and(SelectSignatureFromKey... selectors) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                for (SelectSignatureFromKey selector : selectors) {
                    if (!selector.accept(signature, key, keyRing)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    public static SelectSignatureFromKey or(SelectSignatureFromKey... selectors) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                boolean accept = false;
                for (SelectSignatureFromKey selector : selectors) {
                    accept |= selector.accept(signature, key, keyRing);
                }
                return accept;
            }
        };
    }

    public static SelectSignatureFromKey not(SelectSignatureFromKey selector) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !selector.accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey adapter(SignatureFilter signatureFilter) {
        return adapter(signatureFilter, new Date());
    }

    public static SelectSignatureFromKey adapter(SignatureFilter signatureFilter, Date validationDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signatureFilter.accept(signature, validationDate);
            }
        };
    }
}
