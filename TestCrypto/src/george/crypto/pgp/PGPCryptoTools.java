package george.crypto.pgp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

/**
 * 
 * Copyright George El-Haddad</br>
 * <b>Time stamp:</b> Dec 6, 2012 - 11:41:43 AM<br/>
 * @author George El-Haddad
 * <br/>
 *
 */
public final class PGPCryptoTools {

        static {
                if (Security.getProvider("BC") == null) {
                        Security.addProvider(new BouncyCastleProvider());
                }
        }

        private PGPCryptoTools() {

        }

        public static final List<String> listCertifications(File publicKeyFile) throws IOException {
                FileInputStream keyInputStream = new FileInputStream(publicKeyFile);
                List<String> keyIds = new ArrayList<String>();

                PGPPublicKeyRing pgpPubRing = new PGPPublicKeyRing(PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
                PGPPublicKey pubKey = pgpPubRing.getPublicKey();

                @SuppressWarnings("unchecked")
                Iterator<PGPSignature> sigIter = pubKey.getSignatures();
                while (sigIter.hasNext()) {
                        PGPSignature pgpSig = sigIter.next();
                        long keyId = pgpSig.getKeyID();
                        keyIds.add(Long.toHexString(keyId).toUpperCase());
                }

                return keyIds;
        }

        /**
         * 
         * @param outputFileName - the file name to use for the encrypted output
         * @param inputFileName - the name of the file to encrypt
         * @param pgpKeyRingFile - the PGP public key file
         * @param asciiArmor - true to use ASCII armor
         * @param integrityCheck - true to use integrity checks
         * @throws IOException
         * @throws PGPException
         */
        public static final void encryptFile(File outputFileName, File inputFileName, File pgpKeyRingFile, boolean asciiArmor, boolean integrityCheck) throws IOException, PGPException {
                FileInputStream keyInputStream = new FileInputStream(pgpKeyRingFile);
                PGPPublicKey publicKey = readPublicKey(keyInputStream);

                OutputStream out = null;
                if (asciiArmor) {
                        out = new ArmoredOutputStream(new FileOutputStream(outputFileName));
                }
                else {
                        out = new BufferedOutputStream(new FileOutputStream(outputFileName));
                }

                JcePGPDataEncryptorBuilder PgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                .setWithIntegrityPacket(integrityCheck)
                .setSecureRandom(new SecureRandom())
                .setProvider("BC");

                PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(PgpDataEncryptorBuilder);
                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
                OutputStream dataGeneratorOut = encryptedDataGenerator.open(out, new byte[1 << 16]);
                PGPCompressedDataGenerator compressDataGeneratorOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                PGPUtil.writeFileToLiteralData(compressDataGeneratorOut.open(dataGeneratorOut), PGPLiteralData.BINARY, inputFileName, new byte[1 << 16]);

                compressDataGeneratorOut.close();
                dataGeneratorOut.close();
                out.close();
        }

        /**
         * 
         * @param inputFileName - the file to decrypt
         * @param keyFileName - the PGP key ring file
         * @param passwd - the pass phrase protecting the PGP key ring file
         * @param outputFileName - the file to output the decrypted data
         * @throws IOException on I/O errors
         * @throws PGPException on decryption errors
         */
        public static final void decryptFile(File inputFileName, File keyFileName, char[] passwd, File outputFileName) throws IOException, PGPException {
                InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
                InputStream in = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(inputFileName)));

                PGPObjectFactory pgpObjFactory = new PGPObjectFactory(in);
                PGPEncryptedDataList pgpEncryptedDataList = null;

                Object o = pgpObjFactory.nextObject();
                if (o instanceof PGPEncryptedDataList) {
                        pgpEncryptedDataList = (PGPEncryptedDataList) o;
                }
                else {
                        pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjFactory.nextObject();
                }

                PGPPrivateKey secretKey = null;
                PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
                PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

                @SuppressWarnings("unchecked")
                Iterator<PGPPublicKeyEncryptedData> it = pgpEncryptedDataList.getEncryptedDataObjects();

                while (it.hasNext() && secretKey == null) {
                        publicKeyEncryptedData = it.next();
                        PGPSecretKey pgpSecKey = pgpSecretKeyRingCollection.getSecretKey(publicKeyEncryptedData.getKeyID());

                        if (pgpSecKey != null) {
                                Provider provider = Security.getProvider("BC");
                                secretKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(provider).build()).setProvider(provider).build(passwd));
                        }
                }

                if (secretKey == null) {
                        throw new IllegalArgumentException("secret key for message not found.");
                }

                if (publicKeyEncryptedData == null) {
                        throw new NullPointerException("cannot continue with null public key encryption data.");
                }

                InputStream clear = publicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secretKey));
                PGPObjectFactory plainFact = new PGPObjectFactory(clear);
                PGPCompressedData compressedData = (PGPCompressedData) plainFact.nextObject();
                InputStream compressedStream = new BufferedInputStream(compressedData.getDataStream());
                PGPObjectFactory pgpFact = new PGPObjectFactory(compressedStream);
                Object message = pgpFact.nextObject();

                if (message instanceof PGPLiteralData) {
                        PGPLiteralData literalData = (PGPLiteralData) message;
                        InputStream literalDataInputStream = literalData.getInputStream();
                        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
                        Streams.pipeAll(literalDataInputStream, out);
                        out.close();
                }
                else if (message instanceof PGPOnePassSignatureList) {
                        throw new PGPException("encrypted message contains a signed message - not literal data.");
                }
                else {
                        throw new PGPException("message is not a simple encrypted file - type unknown.");
                }

                if (publicKeyEncryptedData.isIntegrityProtected()) {
                        if (!publicKeyEncryptedData.verify()) {
                                throw new PGPException("message failed integrity check");
                        }
                }

                keyIn.close();
                in.close();
        }

        /**
         * 
         * @param fileToSign - the file to sign
         * @param pgpKeyRingFile - the PGP Key Ring file that will do the signing
         * @param outputFile - the signed file to be outputted
         * @param passphrase - the secret pass phrase of the PGP Private Key 
         * @param asciiArmor - set to true to use ASCII armor mode
         * @throws PGPException 
         * @throws SignatureException 
         * @throws IOException
         */
        public static final void signFile(File fileToSign, File pgpKeyRingFile, File outputFile, char[] passphrase, boolean asciiArmor) throws IOException, PGPException, SignatureException {
                FileInputStream keyInputStream = new FileInputStream(pgpKeyRingFile);
                PGPSecretKey pgpSecretKey = readSecretKey(keyInputStream);
                PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

                @SuppressWarnings("unchecked")
                Iterator<String> it = pgpSecretKey.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                        spGen.setSignerUserID(false, it.next());
                        signatureGenerator.setHashedSubpackets(spGen.generate());
                }

                OutputStream outputStream = null;
                if (asciiArmor) {
                        outputStream = new ArmoredOutputStream(new FileOutputStream(outputFile));
                }
                else {
                        outputStream = new FileOutputStream(outputFile);
                }

                // TODO Compression might have issues with other PGP tools
                PGPCompressedDataGenerator compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
                BCPGOutputStream bcOutputStream = new BCPGOutputStream(compressDataGenerator.open(outputStream));
                // BCPGOutputStream bcOutputStream = new
                // BCPGOutputStream(outputStream);
                signatureGenerator.generateOnePassVersion(false).encode(bcOutputStream);

                PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
                OutputStream literalDataGenOutputStream = literalDataGenerator.open(bcOutputStream, PGPLiteralData.BINARY, fileToSign);
                FileInputStream fis = new FileInputStream(fileToSign);

                int ch;
                while ((ch = fis.read()) >= 0) {
                        literalDataGenOutputStream.write(ch);
                        signatureGenerator.update((byte) ch);
                }

                literalDataGenerator.close();
                fis.close();

                signatureGenerator.generate().encode(bcOutputStream);
                compressDataGenerator.close();
                outputStream.close();
        }

        public static final boolean verifyFile(File fileToVerify, File publicKeyFile) throws IOException, PGPException, SignatureException {
                InputStream in = PGPUtil.getDecoderStream(new FileInputStream(fileToVerify));

                PGPObjectFactory pgpObjFactory = new PGPObjectFactory(in);
                PGPCompressedData compressedData = (PGPCompressedData) pgpObjFactory.nextObject();

                /*
                 * Get the signature from the file
                 */
                pgpObjFactory = new PGPObjectFactory(compressedData.getDataStream());
                PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) pgpObjFactory.nextObject();
                PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

                /*
                 * Get the literal data from the file
                 */
                PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjFactory.nextObject();
                InputStream literalDataStream = pgpLiteralData.getInputStream();

                // -------------------------------------------------------------------

                InputStream keyIn = new FileInputStream(publicKeyFile);
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
                PGPPublicKey key = pgpRing.getPublicKey(onePassSignature.getKeyID());

                FileOutputStream literalDataOutputStream = new FileOutputStream(pgpLiteralData.getFileName());
                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

                int ch;
                while ((ch = literalDataStream.read()) >= 0) {
                        onePassSignature.update((byte) ch);
                        literalDataOutputStream.write(ch);
                }

                literalDataOutputStream.close();

                // -------------------------------------------------------------------

                /*
                 * Get the signature from the written out file
                 */
                PGPSignatureList p3 = (PGPSignatureList) pgpObjFactory.nextObject();
                PGPSignature signature = p3.get(0);

                /*
                 * Verify the two signatures
                 */
                if (onePassSignature.verify(signature)) {
                        return true;
                }
                else {
                        return false;
                }
        }

        public static void signFileDetached(File fileToSign, File pgpKeyRingFile, File outputFile, char[] passphrase, boolean asciiArmor) throws IOException, PGPException, SignatureException {
                InputStream keyInputStream = new BufferedInputStream(new FileInputStream(pgpKeyRingFile));

                OutputStream outputStream = null;
                if (asciiArmor) {
                        outputStream = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));
                }
                else {
                        outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
                }

                PGPSecretKey pgpSecretKey = readSecretKey(keyInputStream);
                PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

                BCPGOutputStream bOut = new BCPGOutputStream(outputStream);
                InputStream fIn = new BufferedInputStream(new FileInputStream(fileToSign));

                int ch;
                while ((ch = fIn.read()) >= 0) {
                        signatureGenerator.update((byte) ch);
                }

                fIn.close();

                signatureGenerator.generate().encode(bOut);

                outputStream.close();
                keyInputStream.close();
        }

        public static boolean verifyFileDetached(File fileToVerify, File signatureFile, File publicKeyFile) throws FileNotFoundException, IOException, PGPException, SignatureException {
                InputStream keyInputStream = new BufferedInputStream(new FileInputStream(publicKeyFile));
                InputStream sigInputStream = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(signatureFile)));

                PGPObjectFactory pgpObjFactory = new PGPObjectFactory(sigInputStream);
                PGPSignatureList pgpSigList = null;

                Object obj = pgpObjFactory.nextObject();
                if (obj instanceof PGPCompressedData) {
                        PGPCompressedData c1 = (PGPCompressedData) obj;
                        pgpObjFactory = new PGPObjectFactory(c1.getDataStream());
                        pgpSigList = (PGPSignatureList) pgpObjFactory.nextObject();
                }
                else {
                        pgpSigList = (PGPSignatureList) obj;
                }

                PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream));
                InputStream fileInputStream = new BufferedInputStream(new FileInputStream(fileToVerify));
                PGPSignature sig = pgpSigList.get(0);
                PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);

                int ch;
                while ((ch = fileInputStream.read()) >= 0) {
                        sig.update((byte) ch);
                }

                fileInputStream.close();
                keyInputStream.close();
                sigInputStream.close();

                if (sig.verify()) {
                        return true;
                }
                else {
                        return false;
                }
        }

        /**
         * <p>Return the first suitable key for signing in the key ring
         * collection. For this case we only expect there to be one key
         * available for signing.</p>
         * 
         * @param input - the input stream of the PGP key ring
         * @return the first suitable PGP secret key found for signing
         * @throws IOException on I/O related errors
         * @throws PGPException on signing errors
         */
        private static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
                PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));
                PGPSecretKey secKey = null;

                @SuppressWarnings("unchecked")
                Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
                while (iter.hasNext() && secKey == null) {
                        PGPSecretKeyRing keyRing = iter.next();

                        @SuppressWarnings("unchecked")
                        Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
                        while (keyIter.hasNext()) {
                                PGPSecretKey key = keyIter.next();
                                if (key.isSigningKey()) {
                                        secKey = key;
                                        break;
                                }
                        }
                }

                if (secKey != null) {
                        return secKey;
                }
                else {
                        throw new IllegalArgumentException("Can't find signing key in key ring.");
                }
        }

        /**
         * <p>Return the first suitable key for encryption in the key ring
         * collection. For this case we only expect there to be one key available
         * for encryption.</p>
         * 
         * @param input - the input stream of the PGP key ring
         * @return the first suitable PGP public key found for encryption
         * @throws IOException on I/O related errors
         * @throws PGPException on signing errors
         */
        private static final PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
                PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input));
                PGPPublicKey pubKey = null;

                @SuppressWarnings("unchecked")
                Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
                while (keyRingIter.hasNext() && pubKey == null) {
                        PGPPublicKeyRing keyRing = keyRingIter.next();

                        @SuppressWarnings("unchecked")
                        Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
                        while (keyIter.hasNext()) {
                                PGPPublicKey key = keyIter.next();
                                if (key.isEncryptionKey()) {
                                        pubKey = key;
                                        break;
                                }
                        }
                }

                if (pubKey != null) {
                        return pubKey;
                }
                else {
                        throw new IllegalArgumentException("Can't find encryption key in key ring.");
                }
        }
}
