package org.pgpainless.key.generation.gen2;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.util.builder.ChildBuilder;
import org.pgpainless.util.builder.ResultCollector;

public class GenerateV2 {

    private PGPKeyPair primaryKeyPair;
    private List<PGPKeyPair> subKeys = new ArrayList<>();

    private final ResultCollector<ChildBuilder<PostPrimaryKey, GenerateV2>> primaryKeyCollector =
            new ResultCollector<ChildBuilder<PostPrimaryKey, GenerateV2>>() {
                @Override
                public void apply(ChildBuilder<PostPrimaryKey, GenerateV2> builder) throws Exception {
                    PrimaryKey primaryKey = (PrimaryKey) builder;
                    GenerateV2.this.primaryKeyPair = primaryKey.keyPair;
                }
            };

    private final ResultCollector<ChildBuilder<PostSigningKey, GenerateV2>> signingKeyCollector =
            new ResultCollector<ChildBuilder<PostSigningKey, GenerateV2>>() {
                @Override
                public void apply(ChildBuilder<PostSigningKey, GenerateV2> builder) throws Exception {
                    SigningSubKey signingKey = (SigningSubKey) builder;
                    GenerateV2.this.subKeys.add(signingKey.keyPair);
                }
            };

    private final ResultCollector<ChildBuilder<PostEncryptionKey, GenerateV2>> encryptionKeyCollector =
            new ResultCollector<ChildBuilder<PostEncryptionKey, GenerateV2>>() {
                @Override
                public void apply(ChildBuilder<PostEncryptionKey, GenerateV2> builder) throws Exception {
                    EncryptionKey encryptionKey = (EncryptionKey) builder;
                    GenerateV2.this.subKeys.add(encryptionKey.keyPair);
                }
            };

    public PrimaryKey withPrimaryKey() {
        return new PrimaryKey(new PostPrimaryKey(), primaryKeyCollector);
    }

    public class PostPrimaryKey {
        public SigningSubKey withSigningSubKey() {
            return new SigningSubKey(new PostSigningKey(), signingKeyCollector);
        }
    }

    public class PostSigningKey {
        public EncryptionKey withEncryptionKey() {
            return new EncryptionKey(new PostEncryptionKey(), encryptionKeyCollector);
        }
    }

    public static class PostEncryptionKey {
        public PrimaryUserId withPrimaryUserId() {
            return new PrimaryUserId();
        }
    }

    public static class PrimaryKey extends PrimaryKeyBuilder implements ChildBuilder<PostPrimaryKey, GenerateV2> {

        private final PostPrimaryKey next;
        private final ResultCollector<ChildBuilder<PostPrimaryKey, GenerateV2>> resultCollector;

        public PrimaryKey(PostPrimaryKey next, ResultCollector<ChildBuilder<PostPrimaryKey, GenerateV2>> resultCollector) {
            super();
            this.next = next;
            this.resultCollector = resultCollector;
        }

        @Override
        public PostPrimaryKey getNext() {
            return next;
        }

        @Override
        public ResultCollector<ChildBuilder<PostPrimaryKey, GenerateV2>> getResultCollector() {
            return resultCollector;
        }

        @Override
        public PrimaryKey rsa(RsaLength length, Date creationTime)
                throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (PrimaryKey) super.rsa(length, creationTime);
        }

        @Override
        public PrimaryKey ecdsa(EllipticCurve curve, Date creationTime)
                throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (PrimaryKey) super.ecdsa(curve, creationTime);
        }

        @Override
        public PrimaryKey eddsa(EdDSACurve curve, Date creationTime)
                throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (PrimaryKey) super.eddsa(curve, creationTime);
        }

        public PrimaryKey withAdditionalKeyFlags(KeyFlag... flags) {

        }
    }

    public static class SigningSubKey extends SigningKeyBuilder implements ChildBuilder<PostSigningKey, GenerateV2> {

        private final PostSigningKey next;
        private final ResultCollector<ChildBuilder<PostSigningKey, GenerateV2>> resultCollector;

        public SigningSubKey(PostSigningKey next, ResultCollector<ChildBuilder<PostSigningKey, GenerateV2>> resultCollector) {
            super();
            this.next = next;
            this.resultCollector = resultCollector;
        }

        @Override
        public PostSigningKey getNext() {
            return next;
        }

        @Override
        public ResultCollector<ChildBuilder<PostSigningKey, GenerateV2>> getResultCollector() {
            return resultCollector;
        }

        @Override
        public SigningSubKey rsa(RsaLength length, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (SigningSubKey) super.rsa(length, creationTime);
        }

        @Override
        public SigningSubKey ecdsa(EllipticCurve curve, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (SigningSubKey) super.ecdsa(curve, creationTime);
        }

        @Override
        public SigningSubKey eddsa(EdDSACurve curve, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (SigningSubKey) super.eddsa(curve, creationTime);
        }
    }

    public static class EncryptionKey extends EncryptionKeyBuilder implements ChildBuilder<PostEncryptionKey, GenerateV2> {

        private final PostEncryptionKey next;
        private final ResultCollector<ChildBuilder<PostEncryptionKey, GenerateV2>> resultCollector;

        public EncryptionKey(PostEncryptionKey next, ResultCollector<ChildBuilder<PostEncryptionKey, GenerateV2>> resultCollector) {
            super();
            this.next = next;
            this.resultCollector = resultCollector;
        }

        @Override
        public PostEncryptionKey getNext() {
            return next;
        }

        @Override
        public ResultCollector<ChildBuilder<PostEncryptionKey, GenerateV2>> getResultCollector() {
            return resultCollector;
        }

        @Override
        public EncryptionKey rsa(RsaLength length, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (EncryptionKey) super.rsa(length, creationTime);
        }

        @Override
        public EncryptionKey ecdh(EllipticCurve curve, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (EncryptionKey) super.ecdh(curve, creationTime);
        }

        @Override
        public EncryptionKey xdh(XDHCurve curve, Date creationTime) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
            return (EncryptionKey) super.xdh(curve, creationTime);
        }
    }

}
