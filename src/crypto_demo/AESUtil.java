package crypto_demo;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * <h2>AES-256 암/복호화 Utils</h2>
 * <p>Bill Pugh Singleton class</p>
 * <p>mode: CBC</p>
 * <p>padding: PKCS5Padding / PKCS7Padding</p>
 * <p>encrypt return -> ( iv + encrypted ) to hex string</p>
 *
 * @author yeonikjo
 * @version 1.0
 */
public class AESUtil implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding";
    private String password;

    private AESUtil() {}

    /**
     * Bill Pugh Singleton class
     */
    private static class CryptoSupply {
        public static final AESUtil ENCODER = new AESUtil();
    }

    /**
     * Singleton Crypto util instance
     *
     * @param password passphrase
     * @return CryptoUtil.class
     */
    public static AESUtil getInstance( String password ) {
        CryptoSupply.ENCODER.password = password;
        return CryptoSupply.ENCODER;
    }

    /**
     * deriving key from password
     */
    private SecretKeySpec getSecretKeySpec() throws Exception {
        if( password == null || password.isEmpty() )
            throw new NullPointerException( "password" );

        // SecretKeyFactory 생성
        // PBKDF2 ( Adaptive Key Derivation Function ) 사용
        SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA1" );
        MessageDigest digest = MessageDigest.getInstance( "SHA-512" );

        // deriving salt from password
        byte[] keyBytes = this.password.getBytes( StandardCharsets.UTF_8 );
        byte[] saltBytes = digest.digest( keyBytes );

        // deriving key from password
        // iteration count 가 높을 수록 보안이 강력해진다
        // 그러나 보안이 강력해질수록 속도가 느려저 성능에 영향을 미칠 수 있다. 취사선택 필요
        // brute-force attack -> defence rainbow attack
        PBEKeySpec pbeKeySpec = new PBEKeySpec( this.password.toCharArray(), saltBytes, 1, 256 );
        Key secretKey = factory.generateSecret( pbeKeySpec );
        return new SecretKeySpec( secretKey.getEncoded(), "AES" );
    }

    /**
     * generate iv
     *
     * @return IvParameterSpec ( 16 byte )
     */
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes( iv );
        return new IvParameterSpec( iv );
    }

    /**
     * AES 암호화
     * <pre>
     *     mode: ECB, padding: PKCS7Padding
     * </pre>
     *
     * @param plainText String
     * @return byte array to hex string ( iv + encrypt )
     */
    public String encrypt( String plainText ) throws Exception {
        // validate
        if( plainText == null || plainText.isEmpty() ) {
            throw new NullPointerException( "plainText" );
        }

        // 암호화 시 무작위 iv 생성
        IvParameterSpec ivParameterSpec = this.generateIv();

        // 암호화 진행
        Cipher cipher = Cipher.getInstance( TRANSFORM );
        cipher.init( Cipher.ENCRYPT_MODE, this.getSecretKeySpec(), ivParameterSpec );
        byte[] encrypted = cipher.doFinal( plainText.getBytes( StandardCharsets.UTF_8 ) );

        // ( iv + encrypted byte array ) to hex string
        return DatatypeConverter.printHexBinary(
                ByteBuffer.allocate( ivParameterSpec.getIV().length + encrypted.length )
                        .put( ivParameterSpec.getIV() )
                        .put( encrypted )
                        .array()
        );
    }

    /**
     * AES 복호화
     * <pre>
     *     mode: CBC, padding: PKCS7Padding
     * </pre>
     *
     * @param cipherText hex string ( iv + encrypt )
     * @return plainText
     */
    public String decrypt( String cipherText ) throws Exception {
        if( cipherText == null || cipherText.isEmpty() ) {
            throw new NullPointerException( "cipherText" );
        }
        cipherText = cipherText.trim();

        // deriving iv byte array and encrypted byte array from cipher string
        byte[] cipherBytes = DatatypeConverter.parseHexBinary( cipherText );
        ByteBuffer buffer = ByteBuffer.wrap( cipherBytes );
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[cipherBytes.length - 16];
        buffer.get( iv, 0, iv.length );
        buffer.get( encrypted, 0, encrypted.length );

        // 복호화 진행
        Cipher cipher = Cipher.getInstance( TRANSFORM );
        cipher.init( Cipher.DECRYPT_MODE, this.getSecretKeySpec(), new IvParameterSpec( iv ) );
        byte[] original = cipher.doFinal( encrypted );

        return new String( original, StandardCharsets.UTF_8 );
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
    public String decyprtCryptoJSAES( String cipherText, String password ) throws Exception {
        if( cipherText == null || cipherText.isEmpty() ) {
            return cipherText;
        }

        // deriving salt from cipher string
        byte[] ctBytes = Base64.getDecoder().decode( cipherText.getBytes( StandardCharsets.UTF_8 ) );
        byte[] saltBytes = Arrays.copyOfRange( ctBytes, 8, 16 );

        // deriving key byte array, iv byte array from password
        byte[] key = new byte[256 / 8];
        byte[] iv = new byte[128 / 8];
        this.evpBytesToKey( password.getBytes( StandardCharsets.UTF_8 ), saltBytes, key, iv );

        // 복호화 진행
        Cipher c = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
        c.init( Cipher.DECRYPT_MODE, new SecretKeySpec( key, "AES" ), new IvParameterSpec( iv ) );
        byte[] ciphertextBytes = Arrays.copyOfRange( ctBytes, 16, ctBytes.length );
        return new String( c.doFinal( ciphertextBytes ) );
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
        // init
        int keySize = 256 / 32;
        int ivSize = 128 / 32;
        int iterations = 1;
        String hashAlgorithm = "MD5";

        int targetKeySize = keySize + ivSize;
        byte[] derivedBytes = new byte[targetKeySize * 4];
        int numberOfDerivedWords = 0;
        byte[] block = null;

        // key hash
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

        // deriving key byte array, iv byte array from hashed password
        System.arraycopy( derivedBytes, 0, resultKey, 0, keySize * 4 );
        System.arraycopy( derivedBytes, keySize * 4, resultIv, 0, ivSize * 4 );
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    private Object readResolve() throws ObjectStreamException {
        return CryptoSupply.ENCODER;
    }

}