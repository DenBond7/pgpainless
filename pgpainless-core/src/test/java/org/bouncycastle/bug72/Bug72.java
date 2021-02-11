package org.bouncycastle.bug72;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.util.Passphrase;

public class Bug72 {

    private static final int BUFFER_SIZE = 1 << 8;
    private final byte[] message = "Hello World!\n".getBytes(StandardCharsets.UTF_8);


    @RepeatedTest(name = "bc {currentRepetition}", value = 1000)
    public void encryptDecrypt() throws IOException, PGPException {
        byte[] encrypted = encryptionBouncycastle(message, getEncryptionPassphrases());
        System.out.println(new String(encrypted, StandardCharsets.UTF_8));
        byte[] decrypted = decryptionPGPainless(encrypted, getDecryptionPassphrases());
        System.out.println(new String(decrypted));
        assertArrayEquals(message, decrypted);
    }

    @RepeatedTest(name = "pgpainless {currentRepetition}", value = 1000)
    public void encryptDecryptPGPainlessOnly() throws IOException, PGPException {
        byte[] encrypted = encryptionPGPainless(message, getEncryptionPassphrases());
        System.out.println(new String(encrypted, StandardCharsets.UTF_8));
        byte[] decrypted = decryptionPGPainless(encrypted, getDecryptionPassphrases());
        assertArrayEquals(message, decrypted);
    }

    /**
     * The value of cipher was created by encrypting 'message' symmetrically using 'password1' and 'password2'
     * in {@link #encryptionBouncycastle(byte[], String[])}.
     * When decrypted with 'password2', decryption fails.
     *
     * I can rule out PGPainless here, as GnuPG also fails to decrypt this message, while others decrypt fine.
     *
     * @throws IOException
     * @throws PGPException
     */
    @Test
    public void decryptFaultyExample() throws IOException, PGPException {
        String cipher = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.68\n" +
                "\n" +
                "jC4ECQMC3HsxjIBGJ7lg9pXvZ93TZpD76Lv+JVxpi3DWKNGRh7QKqhE+FqnMA96n\n" +
                "jC4ECQMCLYvyr3wa8qlggqbncZuhOh6M4o3/d9UkeDHYRY5JwGQ9rfjmYhp45e7d\n" +
                "0kgBS4Xxaim+KHeavy36u/ohad0BkR8sQCWmAlSIfYT7yXR8sKj4zjqIT6/FqGcF\n" +
                "wZ9QgP/uwqVI/d/PC/1CCE2QaJ1Pp9XAQQw=\n" +
                "=9iqo\n" +
                "-----END PGP MESSAGE-----";
        byte[] decrypted = decryptionPGPainless(cipher.getBytes(StandardCharsets.UTF_8), new String[]{"password2"});

        assertArrayEquals(message, decrypted);
    }

    public String[] getEncryptionPassphrases() {
        return new String[] {
                "password1",
                "password2"
        };
    }

    public String[] getDecryptionPassphrases() {
        return new String[] {
                "password2",
                "password1"
        };
    }

    private byte[] decryptionPGPainless(byte[] ciphertext, String[] passwords) throws IOException, PGPException {
        byte[] bytes = null;
        for (String password : passwords) {
            Passphrase passphrase = Passphrase.fromPassword(password);
            DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify().onInputStream(new ByteArrayInputStream(ciphertext))
                    .decryptWith(passphrase)
                    .doNotVerify()
                    .build();
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            Streams.pipeAll(decryptionStream, plainOut);
            decryptionStream.close();
            bytes = plainOut.toByteArray();
        }
        return bytes;
    }

    private byte[] encryptionPGPainless(byte[] plaintext, String[] passwords) throws IOException, PGPException {
        InputStream in = new ByteArrayInputStream(plaintext);
        Passphrase[] passphrases = new Passphrase[passwords.length];
        for (int i = 0; i < passwords.length; i++) {
            String password = passwords[i];
            passphrases[i] = Passphrase.fromPassword(password);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .forPassphrases(passphrases)
                .usingSecureAlgorithms()
                .doNotSign()
                .asciiArmor();

        Streams.pipeAll(in, encryptionStream);
        encryptionStream.close();

        byte[] ciphertext = out.toByteArray();
        return ciphertext;
    }

    /**
     * This method sometimes generates broken ciphertext.
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public byte[] encryptionBouncycastle(byte[] plaintext, String[] passwords) throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
        ArmoredOutputStream armorOutputStream = new ArmoredOutputStream(cipherText);

        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        dataEncryptorBuilder.setWithIntegrityPacket(true);

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);

        for (String password : passwords) {
            encryptedDataGenerator.addMethod(new BcPBEKeyEncryptionMethodGenerator(password.toCharArray()));
        }

        OutputStream encryptionStream = encryptedDataGenerator.open(armorOutputStream, new byte[BUFFER_SIZE]);

        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED);
        OutputStream compressionStream = new BCPGOutputStream(compressedDataGenerator.open(encryptionStream));

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalDataStream = literalDataGenerator.open(compressionStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date(), new byte[BUFFER_SIZE]);

        OutputStream myOutputStream = new MyOutputStream(literalDataStream, compressionStream, encryptionStream, armorOutputStream);
        Streams.pipeAll(in, myOutputStream);
        myOutputStream.close();

        return cipherText.toByteArray();
    }

    // Mimics PGPainless' EncryptionStream
    public static class MyOutputStream extends OutputStream {

        private final OutputStream literalDataStream;
        private final OutputStream compressionStream;
        private final OutputStream encryptionStream;
        private final OutputStream armorStream;

        public MyOutputStream(OutputStream literalDataStream, OutputStream compressionStream, OutputStream encryptionStream, OutputStream armorStream) {
            this.literalDataStream = literalDataStream;
            this.compressionStream = compressionStream;
            this.encryptionStream = encryptionStream;
            this.armorStream = armorStream;
        }

        @Override
        public void write(byte[] b) throws IOException {
            literalDataStream.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            literalDataStream.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            literalDataStream.flush();
        }

        @Override
        public void close() throws IOException {
            literalDataStream.flush();
            literalDataStream.close();

            compressionStream.flush();
            compressionStream.close();

            encryptionStream.flush();
            encryptionStream.close();

            armorStream.flush();
            armorStream.close();
        }

        @Override
        public void write(int i) throws IOException {
            literalDataStream.write(i);
        }
    }

}
