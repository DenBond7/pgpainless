package org.pgpainless.util.selection.signature;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.util.SignatureUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.selection.key.signature.SelectSignatureFromKey;

public abstract class SignatureFilter {

    public abstract boolean accept(PGPSignature signature, Date validationDate);

    public void throwIfNotAcceptable(PGPSignature signature, Date validationDate) throws SignatureSelectionException {
        if (!accept(signature, validationDate)) {
            throw getException(signature, validationDate);
        }
    }

    public abstract SignatureSelectionException getException(PGPSignature signature, Date validationDate);

    public List<PGPSignature> select(List<PGPSignature> signatureList, Date validationDate) {
        List<PGPSignature> accepted = new ArrayList<>();
        for (PGPSignature signature : signatureList) {
            if (accept(signature, validationDate)) {
                accepted.add(signature);
            }
        }
        return accepted;
    }

    public static SignatureFilter isOfType(SignatureType type) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getSignatureType() == type.getCode();
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                return new SignatureSelectionException("Signature type mismatch (expected: " + type + ", actual: " + SignatureType.valueOf(signature.getSignatureType()) + ")");
            }
        };
    }

    public static SignatureFilter isOfVersion(int version) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getVersion() == version;
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                return new SignatureSelectionException("Signature version mismatch (expected: " + version + ", actual: " + signature.getVersion() + ")");
            }
        };
    }

    public static SignatureFilter isCreatedBy(long keyId) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getKeyID() == keyId;
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                return new SignatureSelectionException("Signature creator key ID mismatch (expected: " + Long.toHexString(keyId)
                        + ", actual: " + Long.toHexString(signature.getKeyID()) + ")");
            }
        };
    }

    public static SignatureFilter isCreatedBefore(Date comparisonDate) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getCreationTime().before(comparisonDate);
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                return new SignatureSelectionException("Signature was not created before " + comparisonDate + " (" + signature.getCreationTime() + ")");
            }
        };
    }

    public static SignatureFilter isCreatedAfter(Date comparisonDate) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getCreationTime().after(comparisonDate);
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                return new SignatureSelectionException("Signature was not created after " + comparisonDate + " (" + signature.getCreationTime() + ")");
            }
        };
    }

    public static SignatureFilter isExpiredAt(Date comparisonDate) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                Date expirationDate = SignatureUtils.getSignatureExpirationDate(signature);
                return expirationDate != null && comparisonDate.after(expirationDate);
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                Date expiration = SignatureUtils.getSignatureExpirationDate(signature);
                return new SignatureSelectionException("Signature is not expired at " + comparisonDate
                        + " (expiration: " + (expiration != null ? expiration.toString() : null) + ")");
            }
        };
    }

    public static SignatureFilter isCoveringPointInTime(Date comparisonDate) {
        return and(
                isCreatedBefore(comparisonDate),
                not(isExpiredAt(comparisonDate))
        );
    }

    public static SignatureFilter isWellFormed() {
        return and(
                hasHashedCreationTime(),
                hasNoUnknownCriticalSubpackets()
        );
    }

    public static SignatureFilter hasHashedCreationTime() {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return signature.getHashedSubPackets().getSignatureCreationTime() != null;
            }
        };
    }

    public static SignatureFilter hasNoUnknownCriticalSubpackets() {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return allCriticalSubpacketsKnown(signature.getUnhashedSubPackets())
                        && allCriticalSubpacketsKnown(signature.getHashedSubPackets());
            }

            private boolean allCriticalSubpacketsKnown(PGPSignatureSubpacketVector subpackets) {
                for (int critical : subpackets.getCriticalTags()) {
                    try {
                        SignatureSubpacket.fromCode(critical);
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    public static SignatureFilter isFollowingHashAlgorithmPolicy() {
        return isFollowingHashAlgorithmPolicy(PGPainless.getPolicy());
    }

    public static SignatureFilter isFollowingHashAlgorithmPolicy(Policy policy) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                Policy.HashAlgorithmPolicy hashAlgorithmPolicy;
                if (SignatureType.isRevocationSignature(signature.getSignatureType())) {
                    hashAlgorithmPolicy = policy.getRevocationSignatureHashAlgorithmPolicy();
                } else {
                    hashAlgorithmPolicy = policy.getSignatureHashAlgorithmPolicy();
                }
                return hashAlgorithmPolicy.isAcceptable(signature.getHashAlgorithm());
            }
        };
    }

    public static SignatureFilter and(SignatureFilter... signatureFilters) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                for (SignatureFilter filter : signatureFilters) {
                    if (!filter.accept(signature, validationDate)) {
                        return false;
                    }
                }
                return true;
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                for (SignatureFilter signatureFilter : signatureFilters) {
                    if (!signatureFilter.accept(signature, validationDate)) {
                        SignatureSelectionException underlying = signatureFilter.getException(signature, validationDate);
                        return new SignatureSelectionException("And-operator rejected the signature. Cause: " + underlying.getMessage(), underlying);
                    }
                }
                return null;
            }
        };
    }

    public static SignatureFilter or(SignatureFilter... signatureFilters) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                for (SignatureFilter filter : signatureFilters) {
                    if (filter.accept(signature, validationDate)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                String causes = "" 
                return new SignatureSelectionException("Or-operator rejected signature, as all underlying filters rejected it: [");
            }
        };
    }

    public static SignatureFilter not(SignatureFilter signatureFilter) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature, Date validationDate) {
                return !signatureFilter.accept(signature, validationDate);
            }

            @Override
            public SignatureSelectionException getException(PGPSignature signature, Date validationDate) {
                SignatureSelectionException underlying = signatureFilter.getException(signature, validationDate);
                return new SignatureSelectionException("The statement in the underlying exception was expected to be true, but was not: " + underlying.getMessage(), underlying);
            }
        };
    }

    public static class SignatureSelectionException extends PGPException {

        public SignatureSelectionException(String message, Exception underlying) {
            super(message, underlying);
        }

        public SignatureSelectionException(String message) {
            super(message);
        }
    }
}
