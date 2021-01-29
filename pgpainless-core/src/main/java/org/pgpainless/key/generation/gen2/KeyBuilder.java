package org.pgpainless.key.generation.gen2;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.provider.ProviderFactory;

public class KeyBuilder {

    protected KeyType type;
    protected Date keyCreationTime = new Date();

    public KeyBuilder(KeyType type) {
        this.type = type;
    }

    public KeyBuilder setKeyCreationTime(Date date) {
        if (date != null) {
            this.keyCreationTime = date;
        }
        return this;
    }

    public PGPKeyPair generate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException {
        KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(type.getName(),
                ProviderFactory.getProvider());
        certKeyGenerator.initialize(type.getAlgorithmSpec());

        // Create raw Key Pair
        KeyPair keyPair = certKeyGenerator.generateKeyPair();

        // Form PGP key pair
        PGPKeyPair pgpKeyPair = ImplementationFactory.getInstance().getPGPKeyPair(type.getAlgorithm(), keyPair, new Date());
        return pgpKeyPair;
    }
}
