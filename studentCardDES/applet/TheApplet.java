//JavaCard 2.1.1


package applet;


import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;




public class TheApplet extends Applet {


    private final static byte CLA_TEST				= (byte)0x90;
	private final static byte INS_DES_ECB_NOPAD_ENC           	= (byte)0x20;
    private final static byte INS_DES_ECB_NOPAD_DEC           	= (byte)0x21;
    private final static byte INS_TESTDES_ECB_NOPAD_ENC       	= (byte)0x28;
    private final static byte INS_TESTDES_ECB_NOPAD_DEC       	= (byte)0x29;


	static final byte[] theDESKey = 
		new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };



    // cipher instances
    private Cipher 
	    cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;


    // key objects
			
    private Key 
	    secretDESKey, secretDES2Key, secretDES3Key;


    // "Foo" (name, also sent after termining an operation)
    private byte[] name = { (byte)0x03, (byte)0x46, (byte)0x6F, (byte)0x6F };
    // data's size
    private final static short DTRSIZE = (short)256;//256bytes==2048bits//FOO 8160;//mqos.jpg is 100x20, so...
    // loop variable
    private short i, j, k, x, y;
    // read/write tests array size
    //private final static short WRITINGSIZE = 10;
    // to generate random data
    private final static short RANDOMSIZE = 1000; // <=DTRSIZE
    short offset;
    short length;
    // to perform reading/writing test
    private static final short ARRAY_SIZE = 10;
    private static final short NBWRITEMEM = 100;
    private static final short NBREADMEM = 100;
    private byte[] data;
    private byte[] dataToCipher = {1,2,3,4,5,6,7,8};
    private byte[] ciphered = new byte[8];
    /*
    //size of file, short = byte1 + byte2
    private byte[] fileSize1 = new byte[]{ (byte)0xAB, (byte)0xBC };
    //size of file2, short = byte1 + byte2
    private byte[] fileSize2 = new byte[]{ (byte)0xCD, (byte)0xDE };
    */
    //stack counter
    private byte[] stackCounter = { 0x00 };
    //nb loop DES tests
    private final static short NBTESTSDESCIPHER = 100;
    private final static short NBTESTSDESUNCIPHER = 100;
    /*
    //nb loop RSA tests
    private final static short NBTESTSRSACIPHER = 100;
    private final static short NBTESTSRSAUNCIPHER = 100;
    */
    //private final static short MEMTESTSIZE = 10;
    //VM loop size
    //private final static short VMLOOPSIZE = 30;
    //to test capabilities of the card
    boolean 
	    pseudoRandom, secureRandom,
	    SHA1, MD5, RIPEMD160,
	    keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;

	OwnerPIN pinW,pinR;
	static final byte UPDATECARDKEY				= (byte)0x14;
	static final byte UNCIPHERFILEBYCARD			= (byte)0x13;
	static final byte CIPHERFILEBYCARD			= (byte)0x12;
	static final byte CIPHERANDUNCIPHERNAMEBYCARD		= (byte)0x11;
	static final byte READFILEFROMCARD			= (byte)0x10;
	static final byte WRITEFILETOCARD			= (byte)0x09;
	static final byte UPDATEWRITEPIN			= (byte)0x08;
	static final byte UPDATEREADPIN				= (byte)0x07;
	static final byte DISPLAYPINSECURITY			= (byte)0x06;
	static final byte DESACTIVATEACTIVATEPINSECURITY	= (byte)0x05;
	static final byte ENTERREADPIN				= (byte)0x04;
	static final byte ENTERWRITEPIN				= (byte)0x03;
	static final byte READNAMEFROMCARD			= (byte)0x02;
	static final byte WRITENAMETOCARD			= (byte)0x01;
	final static short SW_PIN_VERIFICATION_REQUIRED = (short)0x6301;
    final static short SW_VERIFICATION_FAILED = (short)0x6300;
	static short datamaxsize = 255;
	
	//tableau qui va contenir le nom
	static byte[] tabName               = new byte[(short)100];
	static byte[] tabFile              = new byte[(short)10000]; //[file_name_length, file_name, nbrApdu, file_tail_length, file_part1, file_part2 ... file_part_end ]
	//static byte tabFile              = (byte)0x00;
	
	//pour DESACTIVATE ACTIVATE PIN SECURITY
	static boolean sec = true;
	
    protected TheApplet() { 
	    initKeyDES(); 
	    initDES_ECB_NOPAD(); 
		byte[] pincodeW = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30}; // PIN code "0000"
		pinW = new OwnerPIN((byte)3,(byte)8);  				// 3 tries 8=Max Size
		pinW.update(pincodeW,(short)0,(byte)4); 				// from pincode, offset 0, length 4
		
		byte[] pincodeR = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30}; // PIN code "0000"
		pinR = new OwnerPIN((byte)3,(byte)8);  				// 3 tries 8=Max Size
		pinR.update(pincodeR,(short)0,(byte)4); 				// from pincode, offset 0, length 4

	    this.register();
    }


    private void initKeyDES() {
	    try {
		    secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		    ((DESKey)secretDESKey).setKey(theDESKey,(short)0);
		    keyDES = true;
	    } catch( Exception e ) {
		    keyDES = false;
	    }
    }


    private void initDES_ECB_NOPAD() {
	    if( keyDES ) try {
		    cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_enc.init( secretDESKey, Cipher.MODE_ENCRYPT );
		    cDES_ECB_NOPAD_dec.init( secretDESKey, Cipher.MODE_DECRYPT );
		    DES_ECB_NOPAD = true;
	    } catch( Exception e ) {
		    DES_ECB_NOPAD = false;
	    }
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
	    new TheApplet();
    }


    public void process(APDU apdu) throws ISOException {
		/* ce qui etait avant dans la methode :
        byte[] buffer = apdu.getBuffer();

        if( selectingApplet() == true )
          return ;

        if( buffer[ISO7816.OFFSET_CLA] != CLA_TEST )
            ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED );

        try { switch( buffer[ISO7816.OFFSET_INS] ) {

			case INS_TESTDES_ECB_NOPAD_ENC: if( DES_ECB_NOPAD ) 
				testCipherGeneric( cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES, NBTESTSDESCIPHER  ); return;
			case INS_TESTDES_ECB_NOPAD_DEC: if( DES_ECB_NOPAD ) 
				testCipherGeneric( cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES, NBTESTSDESUNCIPHER   ); return;

			case INS_DES_ECB_NOPAD_ENC: if( DES_ECB_NOPAD )
				cipherGeneric( apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES ); return;
			case INS_DES_ECB_NOPAD_DEC: if( DES_ECB_NOPAD ) 
				cipherGeneric( apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES  ); return;
				}
			} catch( Exception e ) {
		}*/
		if( selectingApplet() == true )
			return;

		byte[] buffer = apdu.getBuffer();
		

		switch( buffer[1] ) 	{
			case UPDATECARDKEY: updateCardKey( apdu ); break;
			case UNCIPHERFILEBYCARD: uncipherFileByCard( apdu ); break;
			case CIPHERFILEBYCARD: cipherFileByCard( apdu ); break;
			case CIPHERANDUNCIPHERNAMEBYCARD: cipherAndUncipherNameByCard( apdu ); break;
			case READFILEFROMCARD: readFileFromCard( apdu ); break;
			case WRITEFILETOCARD: writeFileToCard( apdu ); break;
			case UPDATEWRITEPIN: updateWritePIN( apdu ); break;
			case UPDATEREADPIN: updateReadPIN( apdu ); break;
			case DISPLAYPINSECURITY: displayPINSecurity( apdu ); break;
			case DESACTIVATEACTIVATEPINSECURITY: desactivateActivatePINSecurity( apdu ); break;
			case ENTERREADPIN: enterReadPIN( apdu ); break;
			case ENTERWRITEPIN: enterWritePIN( apdu ); break;
			case READNAMEFROMCARD: readNameFromCard( apdu ); break;
			case WRITENAMETOCARD: writeNameToCard( apdu ); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }


	private void cipherGeneric( APDU apdu, Cipher cipher, short keyLength ) {
		// Write the method ciphering/unciphering data from the computer.
		// The result is sent back to the computer.
	}


	private void testCipherGeneric( Cipher cipher, short keyLength, short nbLoops ) {
		for( i = 0; i < nbLoops; i++ )
			cipher.doFinal( dataToCipher, (short)0, (short)(keyLength/8), ciphered, (short)0 );
	}
	void updateCardKey( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(buffer, (short)5, theDESKey, (short)0, (short)8);
		initKeyDES();
	}


	void uncipherFileByCard( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		cDES_ECB_NOPAD_dec.doFinal(buffer, (byte)5, byteToShort(buffer[4]), buffer, (byte)5);							
		apdu.setOutgoingAndSend((byte)5,byteToShort(buffer[4] ) );	
	}


	void cipherFileByCard( APDU apdu ) {	
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		cDES_ECB_NOPAD_enc.doFinal(buffer, (byte)5, byteToShort(buffer[4]), buffer, (byte)5);							
		apdu.setOutgoingAndSend((byte)5,byteToShort(buffer[4] ) );														
	
	}


	void cipherAndUncipherNameByCard( APDU apdu ) {
	}

	
	void readFileFromCard( APDU apdu ) {
		if (sec && ! pinR.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);	
			
		//apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();		
		switch(buffer[2]){
			case (byte) 0x00: sendNameFile( apdu ); break;
			case (byte) 0x01: sendNbrApdu( apdu ); break;
			case (byte) 0x02: sendDataFile( apdu ); break;
			case (byte) 0x03: sendLengthTailFile( apdu ); break;
			//case (byte) 0x04: sendTailFile( apdu ); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
	}
	void sendNameFile(  APDU apdu){
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(tabFile,(short)1,buffer,(short)0,(short)tabFile[0]);
		apdu.setOutgoingAndSend( (short)0, (short) tabFile[0] );
	}
	
	void sendNbrApdu(  APDU apdu){
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(tabFile,(short)((short)tabFile[0]+(short)1),buffer,(short)0,(short)2);
		apdu.setOutgoingAndSend( (short)0, (short) 2);
	}
	
	void sendDataFile(  APDU apdu){
		byte[] buffer = apdu.getBuffer();								
		Util.arrayCopy(tabFile,(short)(1+(short)tabFile[0]+2+(short)buffer[3]*(short)datamaxsize),buffer,(short)5,byteToShort(buffer[4]));
		apdu.setOutgoingAndSend( (short)5, byteToShort(buffer[4]) );
	}

		
	void sendLengthTailFile(  APDU apdu){
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(tabFile,(short)((short)tabFile[0]+(short)2),buffer,(short)0,(short)2);
		apdu.setOutgoingAndSend( (short)0, (short) 2);
	}
	

		void sendTailFile(  APDU apdu){
		byte[] buffer = apdu.getBuffer();						
		Util.arrayCopy(tabFile,(short)(1 + (short)tabFile[0] + 2+ (((short)(tabFile[(short)tabFile[0]+1]) * (short)datamaxsize) )) ,buffer,(short)0,byteToShort(tabFile[(short)((short)tabFile[0]+(short)2)]));
		apdu.setOutgoingAndSend( (short)0,(short)tabFile[(short)((short)tabFile[0]+(short)2)] );
	}
	
	
	
	
	
	///////////////////////////////////////////////////////////////////////////////////////////////
	
	
	void writeFileToCard( APDU apdu ) {
		if (sec && ! pinW.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);				
		//apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		switch(buffer[2]){
			case (byte) 0x00: setFile( apdu ); break;
			case (byte) 0x01: setFileName( apdu ); break;
			case (byte) 0x02: setFileTail( apdu ); break;
			case (byte) 0x03: setNbrApdu( apdu ); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	
	void setNbrApdu(APDU apdu ){
	
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		//sauvegarder le nombre d'APDU
		tabFile[1 + ((short)tabFile[0])]=buffer[3];
	}
	void setFile(APDU apdu ){
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		//copier datamaxsize oct du fichier et les mettre dans tabFile a partir de la case n°: (1 + fileName_length + 2 + (nbrApdu * datamaxsize)) - 1
		//offset = (1 + (short)tabFile[0] + 2 + (((short)tabFile[0]+1) * datamaxsize) -1) 		
		Util.arrayCopy(buffer,(short)5,tabFile, (short)(1 + (short)tabFile[0] + 2 + (((short)buffer[3] * datamaxsize) ))  ,(short)(byteToShort(buffer[4]) ));
		
	}
	void setFileName( APDU apdu ){
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		//copier la taille et le nom du fichier dans tabFile
		Util.arrayCopy(buffer,(short)4,tabFile,(short)0,(short)(buffer[4]+1));
		
	}
	void setFileTail( APDU apdu ){
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		//sauvegarder la taille du dernier bloc à la case n°: (1 + (nameFile_length) + 1) +
		tabFile[2 + ((short)tabFile[0])] = buffer[4];
		//copier le dernier bloc dans tabFile à partir a partir de la case n°: (nbrApdu * datamaxsize) + fileName_length + 2
		Util.arrayCopy(buffer,(short)5,tabFile,(short)(1 + (short)tabFile[0] + 2 + (((short)byteToShort(buffer[3]) * (short)datamaxsize ) )),(short)(byteToShort(buffer[4]) ) );//+ (short)1
		
	}
	

	short byteToShort(byte b){
		return (short)((short)255 & b);
	}
	
	void updateWritePIN( APDU apdu ) {
		if (sec && ! pinW.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		pinW = new OwnerPIN((byte)3,(byte)buffer[4]);  				// 3 tries 8=Max Size
		pinW.update(buffer,(short)5,(byte)buffer[4]); 				// from pincode, offset 0, length 4	
	}


	void updateReadPIN( APDU apdu ) {
		if (  sec && ! pinR.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		pinR = new OwnerPIN((byte)3,(byte)buffer[4]);  				// 3 tries 8=Max Size
		pinR.update(buffer,(short)5,(byte)buffer[4]); 				// from pincode, offset 0, length 4
		
	}


	void displayPINSecurity( APDU apdu ) {
		byte[] buffer = apdu.getBuffer();
		if(sec){ 
			buffer[0] = (byte)0x00;
			buffer[1] = (byte)0x00;
		}
		else{
			buffer[0] = (byte)0x01;
			buffer[1] = (byte)0x01;
		}	
		apdu.setOutgoingAndSend( (short)0, (short) 2 );
	}


	void desactivateActivatePINSecurity( APDU apdu ) {
		sec =! sec;
	}


	void enterReadPIN( APDU apdu ) {		
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if( !pinR.check( buffer, (byte)5, buffer[4] ) ) 
			ISOException.throwIt( SW_VERIFICATION_FAILED );		
	}


	void enterWritePIN( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if( !pinW.check( buffer, (byte)5, buffer[4] ) ) 
			ISOException.throwIt( SW_VERIFICATION_FAILED );		
	}


	void readNameFromCard( APDU apdu ) {
		if ( sec && ! pinR.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		
		byte [] buffer = apdu.getBuffer();      
        Util.arrayCopy(tabName,(short)1, buffer,(short) 0,(short)tabName[0]);        
        apdu.setOutgoingAndSend( (short)0, (short) tabName[0] );
	}


	void writeNameToCard( APDU apdu ) {	
		if (sec && ! pinW.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		
		byte[] buffer = apdu.getBuffer();        
        apdu.setIncomingAndReceive();  
        Util.arrayCopy(buffer,(short)4,tabName,(short)0,(byte)(buffer[4]+1));
	}


}
