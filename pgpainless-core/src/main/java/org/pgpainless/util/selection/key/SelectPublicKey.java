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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.selection.userid.SelectUserId;

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class SelectPublicKey {

    private static final Logger LOGGER = Logger.getLogger(SelectPublicKey.class.getName());

    public Set<PGPPublicKey> selectKeysFromKeyRing(@Nonnull PGPKeyRing keyRing) {
        Set<PGPPublicKey> keys = new HashSet<>();
        for (Iterator<PGPPublicKey> i = keyRing.getPublicKeys(); i.hasNext(); ) {
            PGPPublicKey key = i.next();
            if (accept(key)) {
                keys.add(key);
            }
        }
        return keys;
    }

    public abstract boolean accept(PGPPublicKey publicKey);

    public static SelectPublicKey canEncryptStorage() {
        return hasAnyKeyFlag(KeyFlag.ENCRYPT_STORAGE);
    }

    public static SelectPublicKey canEncryptCommunications() {
        return hasAnyKeyFlag(KeyFlag.ENCRYPT_COMMS);
    }

    public static SelectPublicKey canSign() {
        return hasAnyKeyFlag(KeyFlag.SIGN_DATA);
    }

    public static SelectPublicKey canAuthenticate() {
        return hasAnyKeyFlag(KeyFlag.AUTHENTICATION);
    }

    public static SelectPublicKey canCertify() {
        return hasAnyKeyFlag(KeyFlag.CERTIFY_OTHER);
    }

    public static SelectPublicKey hasAnyKeyFlag(KeyFlag... flags) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                PGPSignature signature = (PGPSignature) publicKey.getSignatures().next();
                if (signature == null) {
                    return false;
                }
                boolean hasAnyKeyFlag = false;
                for (KeyFlag flag : flags) {
                    hasAnyKeyFlag |= KeyFlag.hasKeyFlag(signature.getHashedSubPackets().getKeyFlags(), flag);
                }
                return hasAnyKeyFlag;
            }
        };
    }

    public static SelectPublicKey isSubkeyIn(PGPKeyRing keyRing) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                Iterator<PGPSignature> signatures = publicKey.getSignaturesForKeyID(primaryKey.getKeyID());
                while (signatures.hasNext()) {
                    PGPSignature signature = signatures.next();
                    if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                        try {
                            signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), primaryKey);
                            return signature.verifyCertification(primaryKey, publicKey);
                        } catch (PGPException e) {
                            LOGGER.log(Level.WARNING, "Could not verify subkey signature of key " +
                                    Long.toHexString(primaryKey.getKeyID()) + " on key " + Long.toHexString(publicKey.getKeyID()));

                            return false;
                        }
                    }
                }
                return false;
            }
        };
    }

    public static SelectPublicKey isNotRevoked() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                return !publicKey.hasRevocation();
            }
        };
    }

    public static SelectPublicKey hasMatchingUserId(SelectUserId selectUserId) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
                    String userId = it.next();
                    if (selectUserId.accept(userId)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static SelectPublicKey not(SelectPublicKey strategy) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                return !strategy.accept(publicKey);
            }
        };
    }

    public static SelectPublicKey and(SelectPublicKey... strategies) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                boolean accept = true;
                for (SelectPublicKey strategy : strategies) {
                    accept &= strategy.accept(publicKey);
                }
                return accept;
            }
        };
    }

    public static SelectPublicKey or(SelectPublicKey... strategies) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey) {
                boolean accept = false;
                for (SelectPublicKey strategy : strategies) {
                    accept |= strategy.accept(publicKey);
                }
                return accept;
            }
        };
    }
}
