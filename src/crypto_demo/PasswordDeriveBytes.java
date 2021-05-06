package crypto_demo;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordDeriveBytes {

    private byte[] saltValue;
    private int iterationsCount;
    private MessageDigest hash;
    private int state;
    private byte[] password;
    private byte[] initial;
    private byte[] output;
    private byte[] firstBaseOutput;
    private int position;
    private int hashnumber;
    private int skip;

    /**
     *
     * @param strPassword string passphrase
     * @param rgbSalt byte array salt
     */
    public PasswordDeriveBytes( String strPassword, byte[] rgbSalt ) throws NoSuchAlgorithmException {
        this.prepare( strPassword, rgbSalt, "SHA-1", 100 );
    }

    /**
     *
     * @param strPassword string passphrase
     * @param rgbSalt byte array salt
     * @param strHashName hash algorithm
     * @param iterations iterations
     */
    public PasswordDeriveBytes( String strPassword, byte[] rgbSalt, String strHashName, int iterations ) throws NoSuchAlgorithmException {
        this.prepare( strPassword, rgbSalt, strHashName, iterations );
    }

    /**
     * String passphrase -> byte array passphrase
     *
     * @param strPassword string passphrase
     * @param rgbSalt byte array salt
     * @param strHashName hash algorithm
     * @param iterations iterations
     */
    private void prepare( String strPassword, byte[] rgbSalt, String strHashName, int iterations ) throws NoSuchAlgorithmException {
        if( strPassword == null || strPassword.isEmpty() )
            throw new NullPointerException( "strPassword" );

        // String encoding = "ASCII";
        byte[] pwd = strPassword.getBytes( StandardCharsets.UTF_8 );

        this.prepare( pwd, rgbSalt, strHashName, iterations );
    }

    /**
     * initialize instance
     *
     * @param password byte array passphrase
     * @param rgbSalt byte array salt
     * @param strHashName hash algorithm
     * @param iterations iterations
     */
    private void prepare( byte[] password, byte[] rgbSalt, String strHashName, int iterations ) throws NoSuchAlgorithmException {
        if( password == null )
            throw new NullPointerException( "password" );

        this.password = password;

        this.state = 0;
        this.setSalt( rgbSalt );
        this.setHashName( strHashName );
        this.setIterationCount( iterations );

        this.initial = new byte[this.hash.getDigestLength()];
    }


    public byte[] getBytes( int cb ) throws DigestException {

        if( cb < 1 ) {
            throw new IndexOutOfBoundsException( "cb" );
        }
        if( state == 0 ) {
            reset();
            state = 1;
        }

        byte[] result = new byte[cb];
        int cpos = 0;

        int iter = Math.max( 1, this.iterationsCount - 1 );

        if( output == null ) {
            output = initial;
            output = this.digestOutput( iter, output );
        }
        while( cpos < cb ) {
            byte[] output2 = null;
            if( hashnumber == 0 ) {

                output2 = hash.digest( output );

            } else if( hashnumber < 1000 ) {
                byte[] n = Integer.toString( hashnumber ).getBytes();
                output2 = new byte[output.length + n.length];

                System.arraycopy( n, 0, output2, 0, n.length );

                System.arraycopy( output, 0, output2, n.length, output.length );

                output2 = hash.digest( output2 );

            } else {
                throw new SecurityException( "too long" );
            }


            int rem = output2.length - position;
            int l = Math.min( cb - cpos, rem );
            System.arraycopy( output2, position, result, cpos, l );


            cpos += l;
            position += l;
            while( position >= output2.length ) {
                position -= output2.length;
                hashnumber++;
            }

        }


        if( state == 1 ) {

            if( cb > 20 ) {
                skip = 40 - result.length;
            } else {
                skip = 20 - result.length;
            }

            firstBaseOutput = new byte[result.length];
            System.arraycopy( result, 0, firstBaseOutput, 0, result.length );
            state = 2;

        } else if( skip > 0 ) {

            byte[] secondBaseOutput = new byte[( firstBaseOutput.length + result.length )];
            System.arraycopy( firstBaseOutput, 0, secondBaseOutput, 0, firstBaseOutput.length );
            System.arraycopy( result, 0, secondBaseOutput, firstBaseOutput.length, result.length );


            System.arraycopy( secondBaseOutput, skip, result, 0, skip );


            skip = 0;
        }


        return result;

    }

    public byte[] getBytes2( int cb ) throws DigestException {

        if( cb < 1 ) {
            throw new IndexOutOfBoundsException( "cb" );
        }
        if( state == 0 ) {
            reset();
            state = 1;
        }

        byte[] result = new byte[cb];
        int cpos = 0;

        int iter = Math.max( 1, iterationsCount - 1 );

        if( output == null ) {
            output = initial;
            output = digestOutput( iter, output );

        }
        while( cpos < cb ) {
            byte[] output2 = null;
            if( hashnumber == 0 ) {

                output2 = hash.digest( output );

            } else if( hashnumber < 1000 ) {
                byte[] n = Integer.toString( hashnumber ).getBytes();
                output2 = new byte[output.length + n.length];

                System.arraycopy( n, 0, output2, 0, n.length );

                System.arraycopy( output, 0, output2, n.length, output.length );

                output2 = hash.digest( output2 );

            } else {
                throw new SecurityException( "too long" );
            }


            int rem = output2.length - position;
            int l = Math.min( cb - cpos, rem );
            System.arraycopy( output2, position, result, cpos, l );


            cpos += l;
            position += l;
            while( position >= output2.length ) {
                position -= output2.length;
                hashnumber++;
            }

        }


        if( state == 1 ) {

            if( cb > 20 ) {
                skip = 40 - result.length;
            } else if( cb < 21 && cb > 10 ) {
                skip = 20 - result.length;
            } else {
                skip = 10 - result.length;
            }

            firstBaseOutput = new byte[result.length];
            System.arraycopy( result, 0, firstBaseOutput, 0, result.length );
            state = 2;

        } else if( skip > 0 ) {

            byte[] secondBaseOutput = new byte[( firstBaseOutput.length + result.length )];
            System.arraycopy( firstBaseOutput, 0, secondBaseOutput, 0, firstBaseOutput.length );
            System.arraycopy( result, 0, secondBaseOutput, firstBaseOutput.length, result.length );

            skip = 0;
        }


        return result;
    }

    private byte[] digestOutput( int iter, byte[] output2 ) {
        for( int i = 0; i < iter - 1; i++ ) {
            output2 = this.hash.digest( output2 );
        }
        return output2;
    }


    public void reset() throws DigestException {

        state = 0;
        position = 0;
        hashnumber = 0;
        skip = 0;


        if( saltValue != null ) {
            hash.update( password, 0, password.length );
            hash.update( saltValue, 0, saltValue.length );
            hash.digest( initial, 0, initial.length );
        } else {
            initial = hash.digest( password );
        }

    }

    public byte[] getSalt() {
        return this.saltValue;
    }


    public void setSalt( byte[] salt ) {
        if( this.state != 0 )
            throw new SecurityException( "Can't change this property at this stage" );
        this.saltValue = salt;
    }



    public void setHashName( String hashName ) throws NoSuchAlgorithmException {
        if( hashName == null || hashName.isEmpty() )
            throw new NullPointerException( "HashName" );
        if( this.state != 0 ) {
            throw new SecurityException( "Can't change this property at this stage" );
        }
        this.hash = MessageDigest.getInstance( hashName );
    }


    public int getIterationCount() {
        return this.iterationsCount;
    }


    public void setIterationCount( int iterationCount ) {
        if( iterationCount < 1 )
            throw new NullPointerException( "iterationCount" );
        if( this.state != 0 )
            throw new SecurityException( "Can't change this property at this stage" );

        this.iterationsCount = iterationCount;
    }


    private enum MDAlgorithm {
        MD2( "MD2" ),
        MD5( "MD5" ),
        SHA1( "SHA-1" ),
        SHA224( "SHA-224" ),
        SHA256( "SHA-256" ),
        SHA384( "SHA-384" ),
        SHA512( "SHA-512" ),
        SHA512_224( "SHA-512/224" ),
        SHA512_256( "SHA-512/256" );

        private final String algorithm;

        MDAlgorithm( String algorithm ) {
            this.algorithm = algorithm;
        }

        @Override
        public String toString() {
            return this.algorithm;
        }
    }

}
