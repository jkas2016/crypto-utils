package crypto_demo;

/**
 * @author jyi
 */
public class Main {

    public static void main( String[] args ) throws Exception {
        // AES256 -> 암호화
        @SuppressWarnings( "unused" )
        String devkey = "macaront12^^qwermacaront34^^uiop";
        String prodkey = "akzkfhdt34^^uiopakzkfhdt12^^qwer";
        // "X9NwRMU8uLjrW882gMQ1QSaWzmDF_Dz-MmmBLqtyymw="

        String org = "명노건asdfasdfasdfasdf";
        AESUtil encoder = AESUtil.getInstance( prodkey );

        String encStr2 = encoder.encrypt( org );
        System.out.println( "AES256 암호화 -> { " + encStr2 + " }" );

        String encStr3 = encoder.decrypt( encStr2 );
        System.out.println( "AES256 복호화 -> { " + encStr3 + " }" );
    }

}
