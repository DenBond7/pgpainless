package org.pgpainless.util.selection.key;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.algorithm.PublicKeyAlgorithm;

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class SelectSecretKey {

    private static final Logger LOGGER = Logger.getLogger(SelectSecretKey.class.getName());

    public abstract boolean accept(PGPSecretKey secretKey);

    public Set<PGPSecretKey> selectKeysFromKeyRing(@Nonnull PGPSecretKeyRing keyRing) {
        Set<PGPSecretKey> keys = new HashSet<>();
        for (Iterator<PGPSecretKey> i = keyRing.getSecretKeys(); i.hasNext(); ) {
            PGPSecretKey key = i.next();
            if (accept(key)) {
                keys.add(key);
            }
        }
        return keys;
    }

    public static SelectSecretKey isSigningKey() {
        return new SelectSecretKey() {
            @Override
            public boolean accept(PGPSecretKey secretKey) {
                if (!secretKey.isSigningKey()) {
                    LOGGER.log(Level.FINE, "Rejecting key " + Long.toHexString(secretKey.getKeyID()) + " as its algorithm (" +
                            PublicKeyAlgorithm.fromId(secretKey.getPublicKey().getAlgorithm()) + ") is not capable of signing.");
                    return false;
                }

                if (!SelectPublicKey.canSign().accept(secretKey.getPublicKey())) {
                    LOGGER.log(Level.FINE, "Rejecting key " + Long.toHexString(secretKey.getKeyID()) +
                            " as it does not carry the key flag SIGN_DATA.");
                    return false;
                }
                return true;
            }
        };
    }

    public static SelectSecretKey wherePublicKey(SelectPublicKey strategy) {
        return new SelectSecretKey() {
            @Override
            public boolean accept(PGPSecretKey secretKey) {
                return strategy.accept(secretKey.getPublicKey());
            }
        };
    }

    public static SelectSecretKey not(SelectSecretKey strategy) {
        return new SelectSecretKey() {
            @Override
            public boolean accept(PGPSecretKey secretKey) {
                return !strategy.accept(secretKey);
            }
        };
    }

    public static SelectSecretKey and(SelectSecretKey... strategies) {
        return new SelectSecretKey() {
            @Override
            public boolean accept(PGPSecretKey secretKey) {
                boolean accept = true;
                for (SelectSecretKey strategy : strategies) {
                    accept &= strategy.accept(secretKey);
                }
                return accept;
            }
        };
    }

    public static SelectSecretKey or(SelectSecretKey... strategies) {
        return new SelectSecretKey() {
            @Override
            public boolean accept(PGPSecretKey secretKey) {
                boolean accept = false;
                for (SelectSecretKey strategy : strategies) {
                    accept |= strategy.accept(secretKey);
                }
                return accept;
            }
        };
    }
}
