package client;

import java.util.Date;
import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;




public class TheClient {


	
    private final static byte CLA_TEST				= (byte)0x90;
    private final static byte INS_TESTDES_ECB_NOPAD_ENC       	= (byte)0x28;
    private final static byte INS_TESTDES_ECB_NOPAD_DEC       	= (byte)0x29;
    private final static byte INS_DES_ECB_NOPAD_ENC           	= (byte)0x20;
    private final static byte INS_DES_ECB_NOPAD_DEC           	= (byte)0x21;
    private final static byte P1_EMPTY = (byte)0x00;
    private final static byte P2_EMPTY = (byte)0x00;
  
	
    private PassThruCardService servClient = null;
   
    boolean DISPLAY = true;

	boolean loop = true;

	static final byte CLA = (byte) 0x00;
	static final byte P1 = (byte) 0x00;
	static final byte P2 = (byte) 0x00;
	static final byte UPDATECARDKEY = (byte) 0x14;
	static final byte UNCIPHERFILEBYCARD = (byte) 0x13;
	static final byte CIPHERFILEBYCARD = (byte) 0x12;
	static final byte CIPHERANDUNCIPHERNAMEBYCARD = (byte) 0x11;
	static final byte READFILEFROMCARD = (byte) 0x10;
	static final byte WRITEFILETOCARD = (byte) 0x09;
	static final byte UPDATEWRITEPIN = (byte) 0x08;
	static final byte UPDATEREADPIN = (byte) 0x07;
	static final byte DISPLAYPINSECURITY = (byte) 0x06;
	static final byte DESACTIVATEACTIVATEPINSECURITY = (byte) 0x05;
	static final byte ENTERREADPIN = (byte) 0x04;
	static final byte ENTERWRITEPIN = (byte) 0x03;
	static final byte READNAMEFROMCARD = (byte) 0x02;
	static final byte WRITENAMETOCARD = (byte) 0x01;
	static final  short datamaxsize = 255;
	static final  short cipher_datamaxsize = 248;

	

	
    public static void main( String[] args ) throws InterruptedException {
	    new TheClient();
    }


    public TheClient() {
	    try {
		    SmartCard.start();
		    System.out.print( "Smartcard inserted?... " ); 
		    
		    CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null); 
		    
		    SmartCard sm = SmartCard.waitForCard (cr);
		   
		    if (sm != null) {
			    System.out.println ("got a SmartCard object!\n");
		    } else
			    System.out.println( "did not get a SmartCard object!\n" );
		   
		    this.initNewCard( sm ); 
		    
		    SmartCard.shutdown();
	   
	    } catch( Exception e ) {
		    System.out.println( "TheClient error: " + e.getMessage() );
	    }
	    java.lang.System.exit(0) ;
    }

    private ResponseAPDU sendAPDU(CommandAPDU cmd) {
	    return sendAPDU(cmd, true);
    }

    private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
	    ResponseAPDU result = null;
	    try {
		result = this.servClient.sendCommandAPDU( cmd );
		if(display)
			displayAPDU(cmd, result);
	    } catch( Exception e ) {
           	 System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
           	 java.lang.System.exit( -1 );
            }
	    return result;
    }


    /************************************************
     * *********** BEGINNING OF TOOLS ***************
     * **********************************************/


    private String apdu2string( APDU apdu ) {
	    return removeCR( HexString.hexify( apdu.getBytes() ) );
    }


    public void displayAPDU( APDU apdu ) {
	System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
    }


    public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
	System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
	System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
    }


    private String removeCR( String string ) {
	    return string.replace( '\n', ' ' );
    }


    /******************************************
     * *********** END OF TOOLS ***************
     * ****************************************/


    private boolean selectApplet() {
	 boolean cardOk = false;
	 try {
	    CommandAPDU cmd = new CommandAPDU( new byte[] {
                (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
		(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62, 
		(byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
            } );
            ResponseAPDU resp = this.sendAPDU( cmd );
	    if( this.apdu2string( resp ).equals( "90 00" ) )
		    cardOk = true;
	 } catch(Exception e) {
            System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
            java.lang.System.exit( -1 );
        }
	return cardOk;
    }


    private void initNewCard( SmartCard card ) {
	if( card != null )
		System.out.println( "Smartcard inserted\n" );
	else {
		System.out.println( "Did not get a smartcard" );
		System.exit( -1 );
	}

	System.out.println( "ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");


	try {
		this.servClient = (PassThruCardService)card.getCardService( PassThruCardService.class, true );
	} catch( Exception e ) {
		System.out.println( e.getMessage() );
	}

	System.out.println("Applet selecting...");
	if( !this.selectApplet() ) {
		System.out.println( "Wrong card, no applet to select!\n" );
		System.exit( 1 );
		return;
	} else 
		System.out.println( "Applet selected\n" );
       
	mainLoop();
	}

	void updateCardKey() {
		System.out.println("Entrez un mot de passe de de taille 8: ");
		String pass = readKeyboard();
		byte[] passData = pass.getBytes();		
		byte[] head = {CLA, UPDATECARDKEY, P1, P2, (byte)8};
		byte[] apdu = new byte[5+8];
		System.arraycopy(head, 0, apdu, 0, 5);
		System.arraycopy(passData, 0, apdu, 5, 8);		
		this.sendAPDU((new CommandAPDU(apdu)), DISPLAY);	
	}

	void uncipherFileByCard() {
		System.out.println("Entrez le nom du fichier a decrypter : ");
		String s = readKeyboard();
		File file_crypted = new File("encrypted_"+s);
		File file_decrypted = new File("dechifre_"+s);
		FileOutputStream out=null;
		FileInputStream in =null;
		
		try{
			out = new FileOutputStream(file_decrypted);
		}catch(Exception ex){
			System.out.println("erreur d'ouveture du fichier!! "+ex);
		}
		try{
			in = new FileInputStream(file_crypted);
		}
		catch(Exception ex){
			System.out.println("erreur ouverture! "+ex);
		}
		
		byte[] bloc = new byte[cipher_datamaxsize]; 
		int size=0;
		try{
			size = in.read(bloc);
		}catch(Exception e){
		
		}
		
			boolean bool= false;
			byte [] bloc_new = new byte[cipher_datamaxsize];
			int oldSize=0;
			
		while (size!=-1){
		
				 oldSize =size;
			if (bool ){
			
				try{
					//lire le fichier
				
					 size= in.read(bloc);				 
				}catch(IOException ex){
					System.out.println("erreur lecture fichier!! "+ex);
				}
			}else{
				try{
						//lire le fichier
						
						 size= in.read(bloc_new);				 
				}catch(IOException ex){
						System.out.println("erreur lecture fichier!! "+ex);
				}
			}
		try{
			if(size!=-1){
				if(bool){					
						out.write(sans_paddingUncipher(bloc_new,oldSize));
				}else{
						out.write(sans_paddingUncipher(bloc,oldSize));
				}								
			}else{
				
				if(bool){					
						out.write(avec_depaddingUncipher(bloc_new,oldSize));
				}else{
						out.write(avec_depaddingUncipher(bloc,oldSize));
					
				}				
				
			} 
		}catch(Exception e){
			System.out.println("erreur ecriture file "+e);
		}
		
			bool =!bool;
		
		}
		
		try{
			out.close();
		}catch(Exception e){
		
		}
	}
	
	
	byte[] sans_paddingUncipher (byte[] bloc, int n){
		CommandAPDU cmd;
		ResponseAPDU resp;
		byte[] entete = { CLA, UNCIPHERFILEBYCARD, P1, P2};	
					byte[] apdu=new byte[5 +n +1];
							System.arraycopy(entete, 0, apdu, 0, entete.length);
							apdu[4]=(byte)n;							
							System.arraycopy(bloc, 0, apdu, 5, n);
							apdu[4+n+1] = (byte)0;//le champ LE pour que la carte nous renvoi des données
							 cmd = new CommandAPDU(apdu);
							//displayAPDU(cmd);
							resp = this.sendAPDU(cmd, DISPLAY);
							byte[] buff=resp.getBytes();
							byte[] res = new byte[(buff.length -2)];
							System.arraycopy(buff,0, res, 0, (buff.length -2));
							return res;
		
	}
	
	
	byte[] avec_depaddingUncipher (byte[] bloc, int n){
		
		CommandAPDU cmd;
		ResponseAPDU resp;
		byte[] entete = { CLA, UNCIPHERFILEBYCARD, P1, P2};	
					byte[] apdu=new byte[5 +n +1];
							System.arraycopy(entete, 0, apdu, 0, entete.length);
							apdu[4]=(byte)n;							
							System.arraycopy(bloc, 0, apdu, 5, n);
							apdu[4+n+1] = (byte)0;//le champ LE pour que la carte nous renvoi des données
							 cmd = new CommandAPDU(apdu);
							//displayAPDU(cmd);
							resp = this.sendAPDU(cmd, DISPLAY);
							byte[] buff=resp.getBytes();
							byte[] res = new byte[(buff.length -2) - buff[buff.length-3]];
							System.out.println("buff.length : "+buff.length);
							System.out.println("taille du pading : "+buff[buff.length-3]);
							System.arraycopy(buff,0, res, 0, (buff.length -2) - buff[buff.length-3]);
							return res;
	}
	
	
	
	
	
	
	

	void cipherFileByCard() {
		CommandAPDU cmd;
		ResponseAPDU resp;
		System.out.println("Entrez le nom du fichier a chiffrer : ");
		String s = readKeyboard();
		File file_crypted = new File("encrypted_"+s);
		FileOutputStream out=null;
		try{
			out = new FileOutputStream(file_crypted);
		}catch(Exception ex){
			System.out.println("erreur d'ouveture du fichier!! "+ex);
		}
		FileInputStream file =null;
		try{
			file = new FileInputStream(s);
		}
		catch(FileNotFoundException e){
			System.out.println("erreur ouverture! "+e);
		}
		catch(IOException ee){
			System.out.println("erreur lectureee!! "+ee);
		}
		byte[] bloc = new byte[cipher_datamaxsize];
		byte[] bloc2 = new byte[cipher_datamaxsize];
		
		int n=0;
		try{
				//lire le fichier
				 n= file.read(bloc);				 
			}catch(IOException ex){
				System.out.println("erreur lecture fichier!! "+ex);
			}
		boolean bool=false;
		byte[] entete = { CLA, CIPHERFILEBYCARD, P1, P2};
		byte[] apdu = null;
		int i,j,oldSize =0;
			oldSize =n;
		while ( n!=-1 ){
			
			
			if (bool ){
			
			try{
				//lire le fichier
				 oldSize =n;
				 n= file.read(bloc);				 
			}catch(IOException ex){
				System.out.println("erreur lecture fichier!! "+ex);
			}
			
			}else{
			try{
				//lire le fichier
				 oldSize =n;
				 n= file.read(bloc2);				 
			}catch(IOException ex){
				System.out.println("erreur lecture fichier!! "+ex);
			}
			}
			
			
			if (n!=-1){
						if (bool){
							//envoyerBloc(bloc2);
							byte [] buffer = sans_padding(bloc2,oldSize);
							try{
								out.write(buffer, 0, buffer.length - 2);
							}catch(Exception e){
								System.out.println("erreur d'ecriture dans le fichier..!!"+e);
							}
						}
						else{
							//envoyerBloc(bloc);
							byte [] buffer = sans_padding(bloc,oldSize);
							try{
								out.write(buffer, 0, buffer.length - 2);
							}catch(Exception e){
								System.out.println("erreur d'ecriture dans le fichier..!!"+e);
							}
						} 
							
			}else{
					
						if (bool){
							byte [] buffer = padding(bloc2,oldSize);
							try{
								out.write(buffer, 0, buffer.length - 2);
							}catch(Exception e){
								System.out.println("erreur d'ecriture dans le fichier..!!"+e);
							}
						}
						else{
							//envoyerBloc_pading(bloc) avec padding ; 
								byte [] buffer = padding(bloc,oldSize);
							try{
								out.write(buffer, 0, buffer.length - 2);
							}catch(Exception e){
								System.out.println("erreur d'ecriture dans le fichier..!!"+e);
							}
						
						} 							
						
			}
			

			bool=!bool;
		}


		 
		
	}
	
	byte[] sans_padding (byte[] bloc, int n){
	CommandAPDU cmd;
		ResponseAPDU resp;
		byte[] entete = { CLA, CIPHERFILEBYCARD, P1, P2};	
					byte[] apdu=new byte[5 +n +1];
							System.arraycopy(entete, 0, apdu, 0, entete.length);
							apdu[4]=(byte)n;							
							System.arraycopy(bloc, 0, apdu, 5, n);
							apdu[4+n+1] = (byte)0;//le champ LE pour que la carte nous renvoi des données
							 cmd = new CommandAPDU(apdu);
							//displayAPDU(cmd);
							resp = this.sendAPDU(cmd, DISPLAY);
							return resp.getBytes();
		
		}

	byte[] padding (byte[] bloc, int n){
			//envoyerBloc_pading(bloc2) avec padding ; 
		int i= 8 - (n%8);
		CommandAPDU cmd;
		ResponseAPDU resp;
			 
		byte[] apdu=new byte [5+n+i+1];
		byte[] entete = { CLA, CIPHERFILEBYCARD, P1, P2};		
				
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		apdu[4]=(byte)(n + i);
		System.arraycopy(bloc, 0, apdu, 5, n);
		apdu[4+n+i]=(byte)i;
		apdu[4+n+i+1] = (byte)0;//le champ LE pour que la carte nous renvoi des données				
		cmd = new CommandAPDU(apdu);
		resp = this.sendAPDU(cmd, DISPLAY);
		return resp.getBytes();
	
	}
	
	
	
	void cipherAndUncipherNameByCard() {
		
	}
	
	short bytetoshort(byte b){
		return (short)(b&(short)255);	
	}
	
	
	void readFileFromCard() {
		//envoyer une demande du nom du fichier
		byte[] apdu ={CLA, READFILEFROMCARD, P1, P2, (byte)100};
		//send
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
		byte[] fileNameTab = resp.getBytes();
		String msg = "";
		for (int i = 0; i < fileNameTab.length - 2; i++)
			msg += new StringBuffer("").append((char) fileNameTab[i]);
		System.out.println(msg);
		
		File file = new File("recu_"+msg);
		
		//envoyer une demande nombre d'apdu
		//apdu ={CLA, READFILEFROMCARD, 0x01, P2, (byte)2};
		apdu[2] = 0x01; apdu[4] = 0x02;
		//send
		cmd = new CommandAPDU(apdu);
		resp = this.sendAPDU(cmd, DISPLAY);
		byte[] nbrApduData = resp.getBytes();
		short nbrApdu = (short)nbrApduData[0];
		System.out.println("nbr d'apdu a lire: "+nbrApdu);
		short tailleQ =  byteToShort(nbrApduData[1]);
		System.out.println("la taille de la queue: "+tailleQ);
		FileOutputStream out=null;
		//envoyer une demande des parties du fichier
		try{
			out = new FileOutputStream(file);
		}catch(Exception ex){
			System.out.println("erreur d'ouveture du fichier!! "+ex);
		}
		byte[] buffer=null ;
		//apdu ={CLA, READFILEFROMCARD, 0x02, P2, 0x7f};
		apdu[2] = 0x02; apdu[4] = (byte)datamaxsize;
		short i=0;
		while(nbrApdu > 0){

			apdu[3] = (byte)i;
			//send
			cmd = new CommandAPDU(apdu);
			resp = this.sendAPDU(cmd, DISPLAY);
			buffer = resp.getBytes();
			//write(byte[] b, int off, int len)
			try{
				out.write(buffer, 0, buffer.length - 2);
			}catch(Exception e){
				System.out.println("erreur d'ecriture dans le fichier..!!"+e);
			}
			nbrApdu--;
			i++;
		}
		
	
		
		//envoyer une demande de la denière partie du fichier
		if(tailleQ > 0){
			//apdu ={CLA, READFILEFROMCARD, 0x04, P2, (byte)length_tail_file};
			 apdu[4] = (byte)tailleQ;
			//send
			apdu[3] = (byte)i;
			cmd = new CommandAPDU(apdu);
			resp = this.sendAPDU(cmd, DISPLAY);
			buffer = resp.getBytes();
			try{
				out.write(buffer, 0, buffer.length - 2);
			}catch(Exception e){
				System.out.println("erreur d'ecriture dans le fichier..!!"+e);
			}
		}
		try{
			out.close();
		}catch(Exception e){
			System.out.println("erreur fermeture du fichier..!!"+e);
		}
	}

	
	
	void writeFileToCard() {
	
		CommandAPDU cmd;
		ResponseAPDU resp;
		System.out.println("Entrez le nom du fichier a envoyer : ");
		String s = readKeyboard();
		//String s= "zFile.txt";
		byte[] data = s.getBytes();
		
		

		// entete [CLA,WRITENAMETOCARD,P1,P2]
		byte[] entete = { CLA, WRITEFILETOCARD, (byte)0x01, P2, (byte) data.length };
		byte[] apdu = new byte[5 + data.length];
		
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(data, 0, apdu, entete.length, data.length);
		// envoyer
		 cmd = new CommandAPDU(apdu);
		 //displayAPDU(cmd);
		 resp = this.sendAPDU(cmd, DISPLAY);
		
		
		byte [] fileData= new byte[datamaxsize];
		int nb=0;
		byte[] head = {CLA,WRITEFILETOCARD, P1,P2};
		byte[] head1 = {CLA,WRITEFILETOCARD, (byte) 0x02,P2};
		FileInputStream file =null;
		try{
			file = new FileInputStream(s);
		}
		catch(FileNotFoundException e){
			System.out.println("erreur ouverture! "+e);
		}
		catch(IOException ee){
			System.out.println("erreur lectureee!! "+ee);
		}
			
		
		short nbrapdu=0;
		
		while(nb != -1){
		
			try{
				//lire le fichier
				 nb = file.read(fileData);				 
			}catch(IOException ex){
				System.out.println("erreur lecture fichier!! "+ex);
			}
			
			if (nb==datamaxsize){
				 apdu = new byte[5+nb];
				System.arraycopy(head, 0, apdu, 0, head.length);
				apdu[4]=(byte)nb;
				apdu[3]=(byte)nbrapdu;
				nbrapdu++;
				System.out.println("taille du bloc a envoyer: "+nb);
				System.out.println("taille du bloc a envoyer en utilisant(byteToShort) : "+byteToShort((byte)nb));
				System.arraycopy(fileData, 0, apdu, 5, nb);
				System.out.println("taille apdu " +apdu.length);
				cmd = new CommandAPDU(apdu);
				//displayAPDU(cmd);
				resp = this.sendAPDU(cmd, DISPLAY);
			}else{
			if (nb > -1){
				apdu = new byte[5+nb];
				System.arraycopy(head1, 0, apdu, 0, head1.length);
				apdu[4]=(byte)nb;
				apdu[3]=(byte)nbrapdu;
				//apdu[6]=(byte)  

				System.arraycopy(fileData, 0, apdu, 5, nb);
				cmd = new CommandAPDU(apdu);
				resp = this.sendAPDU(cmd, DISPLAY);
			}
			
			
			}
			
		}
		
		/// Envoyer nombre d'apdu
		byte[] apdu2 = {CLA,WRITEFILETOCARD, (byte) 0x03,(byte) nbrapdu};
		cmd = new CommandAPDU(apdu2);
		resp = this.sendAPDU(cmd, DISPLAY);
		
		
	}
	short byteToShort(byte b){
		return (short)((short)255 & b);
	}

	void updateWritePIN() {
		System.out.println("Entrez le nouveau code pin de l'ecriture: ");
		String pinR = readKeyboard();
		byte[] data = pinR.getBytes();
		byte[] head = {CLA, UPDATEWRITEPIN,P1, P2, (byte)data.length};
		byte[] apdu = new byte[data.length + 5];
		System.arraycopy(head, 0, apdu, 0, head.length);
		System.arraycopy(data, 0, apdu, head.length, data.length);
		//send
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void updateReadPIN() {
		System.out.println("Entrez le nouveau code pin de lecture: ");
		String pinR = readKeyboard();
		byte[] data = pinR.getBytes();
		byte[] head = {CLA, UPDATEREADPIN,P1, P2, (byte)data.length};
		byte[] apdu = new byte[data.length + 5];
		System.arraycopy(head, 0, apdu, 0, head.length);
		System.arraycopy(data, 0, apdu, head.length, data.length);
		//send
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void displayPINSecurity() {
		System.out.println("Client send: displayPINSecurity?...");
		//apdu 
		byte[] apdu = { CLA, DISPLAYPINSECURITY};
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
		
		byte[] received = resp.getBytes();
		if(received[0] == 0x00) System.out.println("true");
		else System.out.println("false");
		
	}

	void desactivateActivatePINSecurity() {
		System.out.println("Client send: desactivateActivatePINSecurity...");
		//apdu 
		byte[] apdu = { CLA, DESACTIVATEACTIVATEPINSECURITY,P1,P2};
		
		CommandAPDU cmd = new CommandAPDU(apdu);
		displayAPDU(cmd);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void enterReadPIN() {
		System.out.println("saisissez le code pin de lecture :");
		String pinR = readKeyboard();
		byte[] data = pinR.getBytes();

		// entete 
		byte[] entete = { CLA, ENTERREADPIN, P1, P2, (byte) data.length };
		byte[] apdu = new byte[5 + data.length];
		
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(data, 0, apdu, entete.length, data.length);
		// envoyer
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void enterWritePIN() {
		System.out.println("saisissez le code pin d'ecriture :");
		String pinW = readKeyboard();
		byte[] data = pinW.getBytes();

		// entete 
		byte[] entete = { CLA, ENTERWRITEPIN, P1, P2, (byte) data.length };
		byte[] apdu = new byte[5 + data.length];
		
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(data, 0, apdu, entete.length, data.length);
		// envoyer
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void readNameFromCard() {

		byte[] cmd_ = { CLA, READNAMEFROMCARD, P1, P2, (byte) 0x100 };
		CommandAPDU cmd = new CommandAPDU(cmd_);
		System.out.println("Sending command APDU, data expected...");
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);

		byte[] bytes = resp.getBytes();
		String msg = "";
		for (int i = 0; i < bytes.length - 2; i++)
			msg += new StringBuffer("").append((char) bytes[i]);
		System.out.println(msg);
		
	}

	void writeNameToCard() {
		System.out.println("saisissez le nom :");
		String name = readKeyboard();
		byte[] data = name.getBytes();

		// entete [CLA,WRITENAMETOCARD,P1,P2]
		byte[] entete = { CLA, WRITENAMETOCARD, P1, P2, (byte) data.length };
		byte[] apdu = new byte[5 + data.length];
		
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(data, 0, apdu, entete.length, data.length);
		// envoyer
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	}

	void exit() {
		loop = false;
	}

	void runAction(int choice) {
		switch (choice) {
		case 14:
			updateCardKey();
			break;
		case 13:
			uncipherFileByCard();
			break;
		case 12:
			cipherFileByCard();
			break;
		case 11:
			cipherAndUncipherNameByCard();
			break;
		case 10:
			readFileFromCard();
			break;
		case 9:
			writeFileToCard();
			break;
		case 8:
			updateWritePIN();
			break;
		case 7:
			updateReadPIN();
			break;
		case 6:
			displayPINSecurity();
			break;
		case 5:
			desactivateActivatePINSecurity();
			break;
		case 4:
			enterReadPIN();
			break;
		case 3:
			enterWritePIN();
			break;
		case 2:
			readNameFromCard();
			break;
		case 1:
			writeNameToCard();
			break;
		case 0:
			exit();
			break;
		default:
			System.out.println("unknown choice!");
		}
	}

	String readKeyboard() {
		String result = null;

		try {
			BufferedReader input = new BufferedReader(new InputStreamReader(
					System.in));
			result = input.readLine();
		} catch (Exception e) {
		}

		return result;
	}

	int readMenuChoice() {
		int result = 0;

		try {
			String choice = readKeyboard();
			result = Integer.parseInt(choice);
		} catch (Exception e) {
		}

		System.out.println("");

		return result;
	}

	void printMenu() {
		System.out.println("");
		System.out.println("14: update the DES key within the card");
		System.out.println("13: uncipher a file by the card");
		System.out.println("12: cipher a file by the card");
		System.out.println("11: cipher and uncipher a name by the card");
		System.out.println("10: read a file from the card");
		System.out.println("9: write a file to the card");
		System.out.println("8: update WRITE_PIN");
		System.out.println("7: update READ_PIN");
		System.out.println("6: display PIN security status");
		System.out.println("5: desactivate/activate PIN security");
		System.out.println("4: enter READ_PIN");
		System.out.println("3: enter WRITE_PIN");
		System.out.println("2: read a name from the card");
		System.out.println("1: write a name to the card");
		System.out.println("0: exit");
		System.out.print("--> ");
	}

	void mainLoop() {
		while (loop) {
			printMenu();
			int choice = readMenuChoice();
			runAction(choice);
		}
	}


    private void testDES_ECB_NOPAD( boolean displayAPDUs ) { 
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_ENC);
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_DEC);
    }


    private void testCryptoGeneric( byte typeINS ) {
	    byte[] t = new byte[4];

	    t[0] = CLA_TEST;
	    t[1] = typeINS;
	    t[2] = P1_EMPTY;
	    t[3] = P2_EMPTY;

            this.sendAPDU(new CommandAPDU( t ));
    } 
    
    
    private byte[] cipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_ENC, challenge );
    } 
    
    
    private byte[] uncipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_DEC, challenge );
    } 


    private byte[] cipherGeneric( byte typeINS, byte[] challenge ) {
	    byte[] result = new byte[challenge.length];
	    // TO COMPLETE
	    return result;
    }
    
    
    private void foo() {
	    sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
	    byte[] response;
	    byte[] unciphered; 
	    long d1, d2, seed=0;
	    java.util.Random r = new java.util.Random( seed );

	    byte[] challengeDES = new byte[16]; 		// size%8==0, coz DES key 64bits

	    r.nextBytes( challengeDES );

	    System.out.println( "**TESTING**");
	    testDES_ECB_NOPAD( true );
	    System.out.println( "**TESTING**");
	   
	    System.out.println("\nchallenge:\n" + encoder.encode(challengeDES) + "\n");
	    response = cipherGeneric(INS_DES_ECB_NOPAD_ENC, challengeDES);
	    System.out.println("\nciphered is:\n" + encoder.encode(response) + "\n");
	    unciphered = cipherGeneric(INS_DES_ECB_NOPAD_DEC, response);
	    System.out.print("\nunciphered is:\n" + encoder.encode(unciphered) + "\n");
    }


}
