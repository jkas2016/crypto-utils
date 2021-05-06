package crypto_demo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptoUtils implements Serializable, Cloneable {

    private String transform;
    private SecretKey secret;
    private IvParameterSpec ivspec;

    private CryptoUtils() {
    }

    /**
     * Bill Pugh Singleton class
     */
    private static class CryptoSupply {
        public static final CryptoUtils ENCODER = new CryptoUtils();
    }

    /**
     * Singleton Crypto util instance
     *
     * @param key passphrase
     * @return CryptoUtil.class
     */
    public static CryptoUtils getInstance( Algorithm algorithm, String key ) throws NoSuchAlgorithmException, DigestException {
        byte[] rgbSalt = {
                ( byte ) 66, ( byte ) 33, ( byte ) 18, ( byte ) 110,
                ( byte ) 32, ( byte ) 77, ( byte ) 101, ( byte ) 100,
                ( byte ) 118, ( byte ) 165, ( byte ) 51, ( byte ) 101, ( byte ) 66
        };

        PasswordDeriveBytes deriveBytes = new PasswordDeriveBytes( key, rgbSalt );
        int cb1 = 32, cb2 = 16;
        if( Algorithm.DES == algorithm ) {
            CryptoSupply.ENCODER.transform = "DES/CBC/PKCS5Padding";
            cb1 = 8;
            cb2 = 8;
            CryptoSupply.ENCODER.secret = new SecretKeySpec( deriveBytes.getBytes2( cb1 ), "DES" );
        } else if( Algorithm.RC2 == algorithm ) {
            CryptoSupply.ENCODER.transform = "RC2/CBC/PKCS5Padding";
            cb1 = 16;
            cb2 = 8;
            CryptoSupply.ENCODER.secret = new SecretKeySpec( deriveBytes.getBytes( cb1 ), "RC2" );
        } else if( Algorithm.TripleDES == algorithm ) {
            CryptoSupply.ENCODER.transform = "DESede/CBC/PKCS5Padding";
            cb1 = 24;
            cb2 = 8;
            CryptoSupply.ENCODER.secret = new SecretKeySpec( deriveBytes.getBytes2( cb1 ), "DESede" );
        } else {
            CryptoSupply.ENCODER.transform = "AES/CBC/PKCS5Padding";
            CryptoSupply.ENCODER.secret = new SecretKeySpec( deriveBytes.getBytes( cb1 ), "AES" );
        }

        if( Algorithm.TripleDES == algorithm || Algorithm.DES == algorithm ) {
            CryptoSupply.ENCODER.ivspec = new IvParameterSpec( deriveBytes.getBytes2( cb2 ) );
        } else {
            CryptoSupply.ENCODER.ivspec = new IvParameterSpec( deriveBytes.getBytes( cb2 ) );
        }

        return CryptoSupply.ENCODER;
    }

    /**
     * 암호화
     *
     * @param plainText String
     * @return encrypt hex string
     */
    public String encrypt( String plainText ) throws Exception {
        if( plainText == null || plainText.isEmpty() ) {
            return plainText;
        }

        Cipher cipher = Cipher.getInstance( this.transform );
        cipher.init( Cipher.ENCRYPT_MODE, secret, ivspec );
        byte[] ciphertext = cipher.doFinal( plainText.getBytes( StandardCharsets.UTF_8 ) );

        return Base64.getEncoder().encodeToString( ciphertext );
    }

    /**
     * 복호화
     *
     * @param cipherText encrypt hex string
     * @return plainText
     */
    public String decrypt( String cipherText ) throws Exception {
        if( cipherText == null || cipherText.isEmpty() ) {
            return cipherText;
        }
        cipherText = cipherText.trim();

        Cipher cipher = Cipher.getInstance( this.transform );
        cipher.init( Cipher.DECRYPT_MODE, secret, ivspec );
        byte[] ciphertext = cipher.doFinal( Base64.getDecoder().decode( cipherText.getBytes( StandardCharsets.UTF_8 ) ) );

        return new String( ciphertext, StandardCharsets.UTF_8 );
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    private Object readResolve() throws ObjectStreamException {
        return CryptoSupply.ENCODER;
    }

    public enum Algorithm {
        AES,
        AES_INTERN,
        DES,
        RC2,
        TripleDES,
        Rijndael;

        @Override
        public String toString() {
            return this.name();
        }
    }

}
