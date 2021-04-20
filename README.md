# AES encrypt/decrypt utils
> Bill Pugh Singleton class

## method

```java
/**
 * AES 암호화
 * <pre>
 *     mode: ECB, padding: PKCS5Padding
 * </pre>
 *
 * @param plainText String
 * @return encrypt hex string
 */
public String encrypt( String plainText ) throws Exception
```
```java
/**
 * AES 복호화
 * <pre>
 *     mode: ECB, padding: PKCS5Padding
 * </pre>
 *
 * @param cipherText encrypt hex string
 * @return plainText
 */
public String decrypt( String cipherText ) throws Exception 
```
```java
/**
 * Javascript( CryptoJS ) encrypt -> Java decrypt
 * <pre>
 *     mode: CBC, padding: PKCS7Padding
 * </pre>
 *
 * @param cipherText Base64 String
 * @return plainText String
 */
public String decyprtCryptoJSAES( String cipherText ) throws Exception 
```