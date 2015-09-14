package george.crypto.pbe;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * 
 * Copyright George El-Haddad</br>
 * <b>Time stamp:</b> Dec 6, 2012 - 11:41:43 AM<br/>
 * @author George El-Haddad
 * <br/>
 *
 */
public class TestPbe {

        static {
                Security.addProvider(new BouncyCastleProvider());
        }

        public static void main(String... args) {
                PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
                encryptor.setProviderName("BC");
                encryptor.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
                encryptor.setPoolSize(4);
                encryptor.setSaltGenerator(new RandomSaltGenerator());
                encryptor.setKeyObtentionIterations(100000);
                encryptor.setPasswordCharArray("BadAssPassword12345!".toCharArray());

                String crypted = encryptor.encrypt("Hello World!");
                System.out.println(crypted);

                String plain = encryptor.decrypt(crypted);
                System.out.println(plain);

        }
}
