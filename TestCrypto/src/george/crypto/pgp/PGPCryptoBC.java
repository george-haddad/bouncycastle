package george.crypto.pgp;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.List;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

/**
 * 
 * Copyright George El-Haddad</br>
 * <b>Time stamp:</b> Dec 6, 2012 - 11:41:43 AM<br/>
 * @author George El-Haddad
 * <br/>
 *
 */
public class PGPCryptoBC {

        public PGPCryptoBC() {

        }

        public void generateKeyPair() {
                try {
                        String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";

                        BigInteger primeModulous = PGPKeyTools.getSafePrimeModulus(PGPKeyTools.PRIME_MODULUS_4096_BIT);
                        BigInteger baseGenerator = PGPKeyTools.getBaseGenerator();
                        ElGamalParameterSpec paramSpecs = new ElGamalParameterSpec(primeModulous, baseGenerator);

                        KeyPair dsaKeyPair = PGPKeyTools.generateDsaKeyPair(1024);
                        KeyPair elGamalKeyPair = PGPKeyTools.generateElGamalKeyPair(paramSpecs);

                        PGPKeyRingGenerator pgpKeyRingGen = PGPKeyTools.createPGPKeyRingGenerator(
                                        dsaKeyPair,
                                        elGamalKeyPair,
                                        "Greg House <g.house@gmail.com>",
                                        "TestPass12345!".toCharArray()
                                        );

                        File privateKey = new File(keysDir + File.separator + "secret4.asc");
                        File publicKey = new File(keysDir + File.separator + "public4.asc");

                        PGPKeyTools.exportSecretKey(pgpKeyRingGen, privateKey, true);
                        PGPKeyTools.exportPublicKey(pgpKeyRingGen, publicKey, true);

                        System.out.println("Generated private key: " + privateKey.getAbsolutePath());
                        System.out.println("Generated public key: " + publicKey.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void signFileDetached() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";

                File theFile = new File(filesDir + File.separator + "public3.asc");
                File keyRingFile = new File(keysDir + File.separator + "secret.asc");
                File signatureFile = new File(filesDir + File.separator + "public3.asc.sig");

                try {
                        PGPCryptoTools.signFileDetached(theFile, keyRingFile, signatureFile, "TestPass12345!".toCharArray(), false);
                        System.out.println("File to sign: " + theFile.getAbsolutePath());
                        System.out.println("Signing key: " + keyRingFile.getAbsolutePath());
                        System.out.println("Signed file: " + signatureFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void verifyFileDetached() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File publicKeyFile = new File(keysDir + File.separator + "public.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.txt");
                File signatureFile = new File(filesDir + File.separator + "TheFile.txt.sig");

                try {
                        boolean verified = PGPCryptoTools.verifyFileDetached(signedFile, signatureFile, publicKeyFile);
                        System.out.println("File: " + signedFile.getAbsolutePath());
                        System.out.println("Verified: " + verified);
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void signFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File theFile = new File(filesDir + File.separator + "TheFile.txt");
                File keyRingFile = new File(keysDir + File.separator + "secret.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.pgp");

                try {
                        PGPCryptoTools.signFile(theFile, keyRingFile, signedFile, "TestPass12345!".toCharArray(), false);
                        System.out.println("File to sign: " + theFile.getAbsolutePath());
                        System.out.println("Signing key: " + keyRingFile.getAbsolutePath());
                        System.out.println("Signed file: " + signedFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void verifyFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File publicKeyFile = new File(keysDir + File.separator + "public.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.pgp");

                try {
                        boolean verified = PGPCryptoTools.verifyFile(signedFile, publicKeyFile);
                        System.out.println("File: " + signedFile.getAbsolutePath());
                        System.out.println("Verified: " + verified);
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void encryptFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File textFile = new File(filesDir + File.separator + "TheFile.txt");
                File outputFile = new File(filesDir + File.separator + "TheFile.pgp");
                File publicKeyFile = new File(keysDir + File.separator + "public.asc");

                try {
                        PGPCryptoTools.encryptFile(outputFile, textFile, publicKeyFile, true, true);
                        System.out.println("File: " + textFile.getAbsolutePath());
                        System.out.println("Encrypted to: " + outputFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void decryptFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File textFile = new File(filesDir + File.separator + "TheFile.txt");
                File inputFile = new File(filesDir + File.separator + "TheFile.pgp");
                File secretKeyFile = new File(keysDir + File.separator + "secret.asc");

                try {
                        PGPCryptoTools.decryptFile(inputFile, secretKeyFile, "TestPass12345!".toCharArray(), textFile);
                        System.out.println("File: " + inputFile.getAbsolutePath());
                        System.out.println("Decrypted to: " + textFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void listPublicKeyCertifications() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                File publicKeyFile = new File(keysDir + File.separator + "MrBilly.asc");

                try {
                        System.out.println("The public key was certified by: ");
                        List<String> keyIds = PGPCryptoTools.listCertifications(publicKeyFile);
                        for (String keyId : keyIds) {
                                System.out.println("\t" + keyId);
                        }
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public static void main(String ... args) {
                //Un comment to test different crypto functions
                
                //new PGPCryptoBC().generateKeyPair();
                //new PGPCryptoBC().signFile();
                //new PGPCryptoBC().verifyFile();
                //new PGPCryptoBC().signFileDetached();
                //new PGPCryptoBC().verifyFileDetached();
                //new PGPCryptoBC().encryptFile();
                //new PGPCryptoBC().decryptFile();
                new PGPCryptoBC().listPublicKeyCertifications();
        }
}
