package client;

import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;
import java.net.*;




public class TheClient extends Thread {

	private PassThruCardService servClient = null;

	boolean DISPLAY = true;

	static final byte CLA = (byte) 0x00;
	static final byte P1 = (byte) 0x00;
	static final byte P2 = (byte) 0x00;
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

		mainContent();
	}


	/************************************************/


	void mainContent() {
		start();
		sendMessages();
	}


	public void run() {
		receiveMessages();
	}


	static final int port = 6010;
	static final String broadcast_ip = "255.255.255.255";


	void sendMessages() {
		System.out.println("Typed messages will be sent to all subnetwork.");
		while(true) try {
			String msg = readKeyboard();
			byte[] message = msg.getBytes();
			//chiffrer le message avant de l'envoyer!!			
			byte[] msg_encrypted = encryptMSG(message);
			InetAddress address = InetAddress.getByName(broadcast_ip);
			DatagramPacket packet = new DatagramPacket(msg_encrypted, msg_encrypted.length , address, port);
			DatagramSocket socket = new DatagramSocket();
			socket.send(packet);
		} catch( Exception e ) {}
	}
	byte [] encryptMSG(byte[] msg){
		
		int padding = 8 - msg.length%8; 
		
		byte[] entete = { (byte)0x90, (byte)0x20, P1, P2, (byte) (msg.length+padding) };
		byte[] apdu = new byte[5 + msg.length+padding+1];
		
		apdu[4+msg.length+padding]=(byte)padding;
		apdu[4+msg.length+padding+1]=(byte)0;
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(msg, 0, apdu, entete.length, msg.length);
		
		
		// envoyer
		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
			byte[] buff= resp.getBytes();
			byte[] res= new byte [buff.length-1];
			System.arraycopy(buff, 0, res, 1, buff.length-2);
			res[0]=(byte)(buff.length-2);
			
			return res;
		
	}

	void receiveMessages() {
		System.out.println("Received messages from all subnetwork will be displayed.");
		while(true) try {
			byte[] message = new byte[33];
			DatagramSocket socket = new DatagramSocket(port);
			DatagramPacket packet = new DatagramPacket(message, message.length);
			socket.receive(packet);
			//dechiffrer le message reçu avant de l'afficher!!
			
			//String s = new String(message);
			String s = new String(decryptMSG(message));
			System.out.println(s);
			System.out.println(packet.getAddress().getHostName() + ": " +s);
		} catch( Exception e ) {}
	}
	
	byte [] decryptMSG(byte[] msg){
		
		
		int t = msg[0];
		System.out.println(" la taille de l'apdu  :"+t);
		byte[] entete = { (byte)0x90, (byte)0x21, P1, P2, (byte) (t) };
		byte[] apdu = new byte[6 +t];
		apdu [5 +t]= (byte)0;
		//apdu[4+msg.length+padding]=(byte)padding;
		//apdu[4+msg.length+padding+1]=(byte)0;
		// remplir l'apdu
		System.arraycopy(entete, 0, apdu, 0, entete.length);
		System.arraycopy(msg, 1, apdu, entete.length, msg[0]);
		
		
		// envoyer
		CommandAPDU cmd = new CommandAPDU(apdu);
		displayAPDU(cmd);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
			
			byte []  buff=resp.getBytes();
		buff[buff.length-2]=(byte)0;
		buff[buff.length-3]=(byte)0;
		return buff;
	}

	

	String readKeyboard() {
		String result = null;

		try {
			BufferedReader input = new BufferedReader( new InputStreamReader( System.in ) );
			result = input.readLine();
		} catch( Exception e ) {}

		return result;
	}


	public static void main( String[] args ) throws InterruptedException {
		new TheClient();
	}


}
