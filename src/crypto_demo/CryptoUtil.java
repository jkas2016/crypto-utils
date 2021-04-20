package crypto_demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtil implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;
    private static final String TRANSFORM = "AES/ECB/PKCS5Padding";
    private static String KEY;

    private CryptoUtil() {
    }

    /**
     * Bill Pugh Singleton class
     */
    private static class CryptoSupply {
        public static final CryptoUtil ENCODER = new CryptoUtil();
    }

    /**
     * Singleton Crypto util instance
     *
     * @param KEY passphrase
     * @return CryptoUtil.class
     */
    public static CryptoUtil getInstance( String KEY ) {
        CryptoUtil.KEY = KEY;
        return CryptoSupply.ENCODER;
    }

    /**
     * AES 암호화
     * <pre>
     *     mode: ECB, padding: PKCS5Padding
     * </pre>
     *
     * @param plainText String
     * @return encrypt hex string
     */
    public String encrypt( String plainText ) throws Exception {
        if( plainText == null || plainText.isEmpty() ) {
            return plainText;
        }

        KeyGenerator kgen = KeyGenerator.getInstance( "AES" );
        kgen.init( 128 );

        byte[] raw = KEY.getBytes( StandardCharsets.UTF_8 );
        SecretKeySpec skeySpec = new SecretKeySpec( raw, "AES" );
        Cipher cipher = Cipher.getInstance( TRANSFORM );

        cipher.init( Cipher.ENCRYPT_MODE, skeySpec );
        byte[] encrypted = cipher.doFinal( plainText.getBytes( StandardCharsets.UTF_8 ) );

        return asHex( encrypted );
    }

    /**
     * AES 복호화
     * <pre>
     *     mode: ECB, padding: PKCS5Padding
     * </pre>
     *
     * @param cipherText encrypt hex string
     * @return plainText
     */
    public String decrypt( String cipherText ) throws Exception {
        if( cipherText == null || cipherText.isEmpty() ) {
            return cipherText;
        }
        cipherText = cipherText.trim();

        KeyGenerator kgen = KeyGenerator.getInstance( "AES" );
        kgen.init( 128 );

        byte[] raw = KEY.getBytes( StandardCharsets.UTF_8 );
        SecretKeySpec skeySpec = new SecretKeySpec( raw, "AES" );
        Cipher cipher = Cipher.getInstance( TRANSFORM );

        cipher.init( Cipher.DECRYPT_MODE, skeySpec );
        byte[] original = cipher.doFinal( fromString( cipherText ) );

        return new String( original, StandardCharsets.UTF_8 );
    }

    private static String asHex( byte[] buf ) {
        StringBuilder strbuf = new StringBuilder( buf.length * 2 );
        int i;

        for( i = 0; i < buf.length; i++ ) {
            if( ( ( int ) buf[i] & 0xff ) < 0x10 )
                strbuf.append( "0" );

            strbuf.append( Long.toString( ( int ) buf[i] & 0xff, 16 ) );
        }

        return strbuf.toString();
    }

    /**
     * Javascript( CryptoJS ) encrypt -> Java decrypt
     * <pre>
     *     mode: CBC, padding: PKCS7Padding
     * </pre>
     *
     * @param cipherText Base64 String
     * @return plainText String
     */
    public String decyprtCryptoJSAES( String cipherText ) throws Exception {
        if( cipherText == null || cipherText.isEmpty() ) {
            return cipherText;
        }

        byte[] ctBytes = Base64.getDecoder().decode( cipherText.getBytes( StandardCharsets.UTF_8 ) );
        byte[] saltBytes = Arrays.copyOfRange( ctBytes, 8, 16 );
        byte[] key = new byte[256 / 8];
        byte[] iv = new byte[128 / 8];
        this.evpBytesToKey( "X9NwRMU8uLjrW882gMQ1QSaWzmDF_Dz-MmmBLqtyymw=".getBytes( StandardCharsets.UTF_8 ), saltBytes, key, iv );

        Cipher c = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
        c.init( Cipher.DECRYPT_MODE, new SecretKeySpec( key, "AES" ), new IvParameterSpec( iv ) );

        byte[] ciphertextBytes = Arrays.copyOfRange( ctBytes, 16, ctBytes.length );
        return new String( c.doFinal( ciphertextBytes ) );
    }

    private byte[] fromString( String hex ) {
        int len = hex.length();
        byte[] buf = new byte[( ( len + 1 ) / 2 )];

        int i = 0, j = 0;
        if( ( len % 2 ) == 1 )
            buf[j++] = ( byte ) fromDigit( hex.charAt( i++ ) );

        while( i < len ) {
            buf[j++] = ( byte ) ( ( fromDigit( hex.charAt( i++ ) ) << 4 ) | fromDigit( hex
                    .charAt( i++ ) ) );
        }
        return buf;
    }

    private int fromDigit( char ch ) {
        if( ch >= '0' && ch <= '9' )
            return ch - '0';
        if( ch >= 'A' && ch <= 'F' )
            return ch - 'A' + 10;
        if( ch >= 'a' && ch <= 'f' )
            return ch - 'a' + 10;

        throw new IllegalArgumentException( "invalid hex digit '" + ch + "'" );
    }

    /**
     * key derivation ( password-based approach )
     * <pre>
     *     Hashing Algorithm : MD5
     *     Iteration : 1
     * </pre>
     *
     * @param password  byte[]
     * @param salt      byte[]
     * @param resultKey byte[]
     * @param resultIv  byte[]
     */
    private void evpBytesToKey( byte[] password, byte[] salt, byte[] resultKey, byte[] resultIv ) throws NoSuchAlgorithmException {
        int keySize = 256 / 32;
        int ivSize = 128 / 32;
        int iterations = 1;
        String hashAlgorithm = "MD5";

        int targetKeySize = keySize + ivSize;
        byte[] derivedBytes = new byte[targetKeySize * 4];
        int numberOfDerivedWords = 0;
        byte[] block = null;
        MessageDigest hasher = MessageDigest.getInstance( hashAlgorithm );
        while( numberOfDerivedWords < targetKeySize ) {
            if( block != null ) {
                hasher.update( block );
            }
            hasher.update( password );
            block = hasher.digest( salt );
            hasher.reset();

            // Iterations
            for( int i = 1; i < iterations; i++ ) {
                block = hasher.digest( block );
                hasher.reset();
            }

            System.arraycopy( block, 0, derivedBytes, numberOfDerivedWords * 4,
                    Math.min( block.length, ( targetKeySize - numberOfDerivedWords ) * 4 ) );

            numberOfDerivedWords += block.length / 4;
        }

        System.arraycopy( derivedBytes, 0, resultKey, 0, keySize * 4 );
        System.arraycopy( derivedBytes, keySize * 4, resultIv, 0, ivSize * 4 );
    }

}