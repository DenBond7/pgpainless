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
package org.pgpainless.util.selection.key;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.selection.key.signature.SelectSignatureFromKey;

public abstract class SelectPublicKey {

    public abstract boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing);

    public List<PGPPublicKey> selectPublicKeys(PGPKeyRing keyRing) {
        List<PGPPublicKey> selected = new ArrayList<>();
        List<PGPPublicKey> publicKeys = CollectionUtils.iteratorToList(keyRing.getPublicKeys());
        for (PGPPublicKey publicKey : publicKeys) {
            if (accept(publicKey, keyRing)) {
                selected.add(publicKey);
            }
        }
        return selected;
    }

    public PGPPublicKey firstMatch(PGPKeyRing keyRing) {
        List<PGPPublicKey> selected = selectPublicKeys(keyRing);
        if (selected.isEmpty()) {
            return null;
        }
        return selected.get(0);
    }

    public static SelectPublicKey isPrimaryKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return publicKey.isMasterKey() && keyRing.getPublicKey().getKeyID() == publicKey.getKeyID();
            }
        };
    }

    public static SelectPublicKey isSubKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                if (isPrimaryKey().accept(publicKey, keyRing)) {
                    return false;
                }
                PGPPublicKey primaryKey = keyRing.getPublicKey();
                PGPSignature primaryKeyBindingSig = (PGPSignature) publicKey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode()).next();
                return false;
            }
        };
    }

    public static SelectPublicKey validEncryptionKeys(String userId) {
        return validEncryptionKeys(userId, new Date());
    }

    public static SelectPublicKey validEncryptionKeys(String userId, Date validationDate) {
        return new SelectPublicKey() {
        }
    }

    public static SelectPublicKey isRevoked() {
        return or(
                and(
                        SelectPublicKey.isPrimaryKey(),
                        SelectPublicKey.hasKeyRevocationSignature()
                ),
                and(
                        isSubKey(),
                        or(
                                SelectPublicKey.hasSubkeyRevocationSignature(),
                                SelectPublicKey.isSubkeyOfRevokedPrimaryKey()
                        )
                )
        );
    }

    private static SelectPublicKey hasKeyRevocationSignature() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                Iterator<PGPSignature> it = publicKey.getSignatures();
                while (it.hasNext()) {
                    PGPSignature signature = it.next();
                    if (SelectSignatureFromKey.isValidKeyRevocationSignature(publicKey).accept(signature, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    private static SelectPublicKey hasSubkeyRevocationSignature() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                Iterator<PGPSignature> it = publicKey.getKeySignatures();
                while (it.hasNext()) {
                    PGPSignature signature = it.next();
                    if (SelectSignatureFromKey.isValidSubkeyRevocationSignature(publicKey, keyRing.getPublicKey()).accept(signature, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    private static SelectPublicKey isSubkeyOfRevokedPrimaryKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return isSubKey().accept(publicKey, keyRing)
                        && SelectPublicKey.hasKeyRevocationSignature().accept(keyRing.getPublicKey(), keyRing);
            }
        };
    }

    public static SelectPublicKey hasKeyFlag(KeyFlag keyFlag) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(HashAlgorithm hashAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(CompressionAlgorithm compressionAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey and(SelectPublicKey... selectors) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                for (SelectPublicKey selector : selectors) {
                    if (!selector.accept(publicKey, keyRing)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    public static SelectPublicKey or(SelectPublicKey... selectors) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                boolean accept = false;
                for (SelectPublicKey selector : selectors) {
                    accept |= selector.accept(publicKey, keyRing);
                }
                return accept;
            }
        };
    }

    public static SelectPublicKey not(SelectPublicKey selector) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return !selector.accept(publicKey, keyRing);
            }
        };
    }
}
