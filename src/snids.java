import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.net.UDPPacket;

public class snids  {
	
	private String rules_filename, pcap_filename;
	
	public static String host;
	public static Scanner scanner;
	public static ArrayList<Rule> rules = new ArrayList<Rule>();
	public static ArrayList<Session> sessions = new ArrayList<Session>();
	public static ArrayList<Session> udp_sessions = new ArrayList<Session>();
	public static ArrayList<Stream> streams = new ArrayList<Stream>();
	public Rule new_rule;

	public snids(String rules_filename, String pcap_filename) {
		super();
		this.rules_filename = rules_filename;
		this.pcap_filename = pcap_filename;
	}

	public void run() throws Exception {
		
		//parse rules.txt
		parseRules(rules_filename);

		try {
			PacketCapture packetCapture = new PacketCapture();

			packetCapture.openOffline(pcap_filename);

			packetCapture.addPacketListener(new IDSListener());
			
			packetCapture.capture(-1);

		} catch (CaptureFileOpenException e) {
			e.printStackTrace();
		}
		catch (CapturePacketException e2) {
			return;
		}

//		// JPCAP
//				//open a file to read saved packets
//		JpcapCaptor captor=JpcapCaptor.openFile(pcap_filename);
//
//		while(true){
//			//read a packet from the opened file
//			Packet packet=captor.getPacket();
//			//if some error occurred or EOF has reached, break the loop
//			if(packet==null || packet==Packet.EOF) break;
//
//			filterPacket(packet);	
//			
//		}
//		
//		
////		for (Rule r : rules)
////			r.print();
//			
//		captor.close();
		
	}
	
	public void filterPacket(Packet p) {
		
		if (p instanceof TCPPacket) {
			filterTCPPacket((TCPPacket)p);
			filterTCCPakcetStream((TCPPacket)p);
		}
		else if (p instanceof UDPPacket)
			filterUDPPacket((UDPPacket)p);
					
	}
	
	public void filterTCCPakcetStream(TCPPacket p) {

		//System.out.println("Stream of TCP");

		String remote_ip = "";
		int local_port, remote_port;
		
		int type = 0, SRC=0, DEST = 1; // 0 we are src, 1 we are dest
		
		// Set locale and remote info
		if (p.getSourceAddress().equalsIgnoreCase(host)) {
			type = SRC;
			remote_ip = p.getDestinationAddress();
			remote_port = p.getDestinationPort();
			local_port = p.getSourcePort();
		}
		else  if (p.getDestinationAddress().equalsIgnoreCase(host)) {
			type = DEST;
			remote_ip = p.getSourceAddress();
			remote_port = p.getSourcePort();
			local_port = p.getDestinationPort();
		}
		else
			return; // TODO
		
		/** GET STREAM OR CREATE **/
		boolean start_stream = (p.isSyn() && !p.isAck());
		boolean delete_stream = p.isFin();
		Stream stream = null;
		if (!start_stream) {
			for (Stream s: streams) {
//				System.out.println(s.remote_ip + " "+ remote_ip);
//				System.out.println(s.remote_port + " "+ remote_port);
//				System.out.println(s.local_port + " "+ local_port);
				if (s.remote_ip.equalsIgnoreCase(remote_ip) 
						&& s.remote_port == remote_port
						&& s.local_port == local_port) {
					stream = s;
					start_stream = false;
				}
			}
		}
		else {
			stream = new Stream(remote_ip, local_port, remote_port);
			streams.add(stream);
		}

		
		// If inside a stream
		if (stream!=null) {
			
			// Delete 
//			if (type == DEST)
//				for (TCPPacket packet : stream.recvs) {
//					if(packet.getSequenceNumber() == p.getSequenceNumber())
//						return;
//				}
//			if (type == SRC)
//				for (TCPPacket packet : stream.sends) {
//					if(packet.getSequenceNumber() == p.getSequenceNumber())
//						return;
//				}

//			System.out.println(stream);

			stream.addPacket(p);

			if (p.isFin()) {
				stream.searchAttacks();
				streams.remove(stream);
			}
		}
		
	}
	
	public void filterTCPPacket(TCPPacket p) {
		
		String remote_ip = "";
		int local_port, remote_port;
		
		int type = 0, SRC=0, DEST = 1; // 0 we are src, 1 we are dest
		
		// Set locale and remote info
		if (p.getSourceAddress().equalsIgnoreCase(host)) {
			type = SRC;
			remote_ip = p.getDestinationAddress();
			remote_port = p.getDestinationPort();
			local_port = p.getSourcePort();
		}
		else  if (p.getDestinationAddress().equalsIgnoreCase(host)) {
			type = DEST;
			remote_ip = p.getSourceAddress();
			remote_port = p.getSourcePort();
			local_port = p.getDestinationPort();
		}
		else
			return; // TODO
		

		/** Check the sessions **/
		boolean new_session = true;
		boolean delete_session = false;
		Session s = null;
		for (Session ses: sessions) {
			if (ses.remote_ip.equalsIgnoreCase(remote_ip) 
					&& ses.remote_port == remote_port
					&& ses.local_port == local_port) {
				new_session = false;
				s = ses;
				if (p.isFin())
					delete_session = true;
			}
		}
		if (new_session) {
			s = new Session(remote_ip, local_port, remote_port);
			sessions.add(s);
		}

		// Check for every rule
		for (int i=0; i<rules.size(); i++) {

			Rule r = rules.get(i);
			boolean match = true;

			if (!r.type.equalsIgnoreCase("protocol")) continue; // only protocl type

			if (!r.proto.equalsIgnoreCase("tcp") && !r.proto.equalsIgnoreCase("any")) continue;

			// check ip
			if (!r.ip.equalsIgnoreCase("any")) {
				// if we are dest, check src ip
				if (type == DEST && !p.getSourceAddress().equalsIgnoreCase(r.ip)) {
					match = false;
				}
			}

			// Check remote port
			if (!r.remote_port.equalsIgnoreCase("any")) {
				if (type == DEST && p.getSourcePort() != Integer.parseInt(r.remote_port))
					match = false;
			}

			
			// Check local port
			if (!r.local_port.equalsIgnoreCase("any")) {
				if (type == DEST && p.getDestinationPort() != Integer.parseInt(r.local_port))
					match = false;
			}

			if (!match) continue;


			/******** SESSION ********/
			int index = s.rules_status.get(i);
			if (type == SRC) {
				if (r.patterns_types.get(index).equals("send")) {
					boolean match_send = false;
					Pattern regex = Pattern.compile(r.patterns.get(index), Pattern.DOTALL);
					String candidateString = new String(p.getData(),0);
//System.out.println("Candidate string in send: "+candidateString);
					Matcher matcher = regex.matcher(candidateString);	
					while (matcher.find()) {
//						System.out.println(matcher.group());
						match_send = true;
					}
					// Check flag
					Flags flags = r.flags.get(index);
					if ((flags.A && !p.isAck())) match_send = false; 
					if ((flags.F && !p.isFin())) match_send = false; 
					if ((flags.S && !p.isSyn())) match_send = false; 
					if ((flags.P && !p.isPsh())) match_send = false; 
					if ((flags.R && !p.isRst())) match_send = false; 
					if ((flags.U && !p.isUrg())) match_send = false; 
					if (match_send) {
						index++;
						s.rules_status.set(i,index);
						if (index == r.patterns.size()) {
							attackFound(r.name);
							s.rules_status.set(i,0);
						}
					}
				}
			}
			else {
				if (rules.get(i).patterns_types.get(index).equals("recv")) {
					boolean match_recv = false;
					Pattern regex = Pattern.compile(r.patterns.get(index), Pattern.DOTALL);
					String candidateString = new String(p.getData(),0);
//System.out.println("Candidate string in recv: "+candidateString);
					Matcher matcher = regex.matcher(candidateString);	
					while (matcher.find()) {
						match_recv = true;
					}
					// Check flag
					Flags flags = r.flags.get(index);
					if ((flags.A && !p.isAck())) match_recv = false; 
					if ((flags.F && !p.isFin())) match_recv = false; 
					if ((flags.S && !p.isSyn())) match_recv = false; 
					if ((flags.P && !p.isPsh())) match_recv = false; 
					if ((flags.R && !p.isRst())) match_recv = false; 
					if ((flags.U && !p.isUrg())) match_recv = false; 
					if (match_recv) {
						index++;
						s.rules_status.set(i,index);
						if (index == r.patterns.size()) {
							attackFound(r.name);
							s.rules_status.set(i,0);
						}
					}
				}
			}
			/******** END SESSION ********/

		}
				
		// If FIN, delete session
		if (delete_session)
			sessions.remove(s);
		
	}
	
	public void filterUDPPacket(UDPPacket p) {

		//System.out.println("UdpPacket");
		
		String remote_ip = "";
		int local_port, remote_port;
		
		int type = 0, SRC=0, DEST = 1; // 0 we are src, 1 we are dest
		
		// Set locale and remote info
		if (p.getSourceAddress().equalsIgnoreCase(host)) {
			type = SRC;
			remote_ip = p.getDestinationAddress();
			remote_port = p.getDestinationPort();
			local_port = p.getSourcePort();
		}
		else  if (p.getDestinationAddress().equalsIgnoreCase(host)) {
			type = DEST;
			remote_ip = p.getSourceAddress();
			remote_port = p.getSourcePort();
			local_port = p.getDestinationPort();
		}
		else
			return; // TODO

		/** Check the sessions **/
		boolean new_session = true;
		Session s = null;
		for (Session ses: udp_sessions) {
			if (ses.remote_ip.equalsIgnoreCase(remote_ip) 
					&& ses.remote_port == remote_port
					&& ses.local_port == local_port) {
				new_session = false;
				s = ses;
			}
		}
		if (new_session) {
			s = new Session(remote_ip, local_port, remote_port);
			udp_sessions.add(s);
		}

		// Check for every rule
		for (int i=0; i<rules.size(); i++) {

			Rule r = rules.get(i);
			boolean match = true;

			if (!r.type.equalsIgnoreCase("protocol")) continue; // only protocl type

			if (!r.proto.equalsIgnoreCase("udp") && !r.proto.equalsIgnoreCase("any")) continue;

			// check ip
			if (!r.ip.equalsIgnoreCase("any")) {
				// if we are dest, check src ip
				if (type == DEST && !p.getSourceAddress().equalsIgnoreCase(r.ip)) {
					match = false;
				}
			}

			// Check remote port
			if (!r.remote_port.equalsIgnoreCase("any")) {
				if (type == DEST && p.getSourcePort() != Integer.parseInt(r.remote_port))
					match = false;
			}

			
			// Check local port
			if (!r.local_port.equalsIgnoreCase("any")) {
				if (type == DEST && p.getDestinationPort() != Integer.parseInt(r.local_port))
					match = false;
			}


			if (!match) continue;

			/******** SESSION ********/
			int index = s.rules_status.get(i);
			if (type == SRC) {
				if (r.patterns_types.get(index).equals("send")) {
					boolean match_send = false;
					Pattern regex = Pattern.compile(r.patterns.get(index), Pattern.DOTALL);
					String candidateString = new String(p.getData(),0);
//System.out.println("Candidate string in send: "+candidateString);
					Matcher matcher = regex.matcher(candidateString);	
					while (matcher.find()) {
						match_send = true;
					}
					if (match_send) {
						index++;
						s.rules_status.set(i,index);
						if (index == r.patterns.size()) {
							attackFound(r.name);
							s.rules_status.set(i,0);
						}
					}
				}
			}
			else {
				if (rules.get(i).patterns_types.get(index).equals("recv")) {
					boolean match_recv = false;
					Pattern regex = Pattern.compile(r.patterns.get(index), Pattern.DOTALL);
					String candidateString = new String(p.getData(),0);
					Matcher matcher = regex.matcher(candidateString);	
//System.out.println("Candidate string in recv: "+candidateString);
					while (matcher.find()) {
						match_recv = true;
					}
					if (match_recv) {
						index++;
						s.rules_status.set(i,index);
						if (index == r.patterns.size()) {
							attackFound(r.name);
							s.rules_status.set(i,0);
						}
					}
				}
			}
			/******** END SESSION ********/
		}
				
	}
	
		
	// Parse the rules
	public void parseRules(String filename) {

		try {

			File fFile = new File(filename);  

			//Note that FileReader is used, not File, since File is not Closeable
			scanner = new Scanner(new FileReader(fFile));
			
			while ( scanner.hasNextLine() ){
				
		        processLine( scanner.nextLine() );
		        
		      }
			rules.add(new_rule);

			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			scanner.close();
		}

	}
	
	// process a line
	public void processLine(String aLine){
		//use a second Scanner to parse the content of each line 
		Scanner line_scanner = new Scanner(aLine);
		line_scanner.useDelimiter("=");
		
		if ( line_scanner.hasNext() ){
		
			String field = line_scanner.next().trim();
			String value = line_scanner.next().trim();
			
			Flags f = new Flags(false,false,false,false,false,false);
			
			// If flags
			if (line_scanner.hasNext()) {
				String flags = line_scanner.next().trim();
				Scanner char_scanner = new Scanner(flags);
				for(int i=0; i<flags.length(); i++) {
					char c = char_scanner.findInLine(".").charAt(0);
					String s = String.valueOf(c);
			    	if (s.equalsIgnoreCase("S")) f.S = true;
			    	if (s.equalsIgnoreCase("A")) f.A = true;
			    	if (s.equalsIgnoreCase("R")) f.R = true;
			    	if (s.equalsIgnoreCase("F")) f.F = true;
			    	if (s.equalsIgnoreCase("P")) f.P = true;
			    	if (s.equalsIgnoreCase("U")) f.U = true;
			    }
				
			}	
						
			if (field.trim().toLowerCase().equals("host"))
				host = value;
			
			// if name, a new rule is found, so save the previous and create the new rule
			else if (field.toLowerCase().equals("name")) {
				if (new_rule!= null) // first time is null
					rules.add(new_rule);
				new_rule = new Rule(value);
			}
			
			else if (field.toLowerCase().equals("type"))
				new_rule.type = value;
			
			else if (field.toLowerCase().equals("proto"))
				new_rule.proto = value;
			
			else if (field.toLowerCase().equals("local_port"))
				new_rule.local_port = value;
			
			else if (field.toLowerCase().equals("remote_port"))
				new_rule.remote_port = value;
			
			else if (field.toLowerCase().equals("ip"))
				new_rule.ip = value;
			
			else if (field.toLowerCase().equals("recv")) {
				new_rule.patterns_types.add("recv");
				new_rule.patterns.add(value.substring(1).substring(0, value.lastIndexOf("\"")-1));
				new_rule.flags.add(f);
			}
			
			else if (field.toLowerCase().equals("send")) {
				new_rule.patterns_types.add("send");
				new_rule.patterns.add(value.substring(1).substring(0, value.lastIndexOf("\"")-1));
				new_rule.flags.add(f);
			}
						
		}
		else {
			//log("Empty or invalid line. Unable to process.");
		}
		
		//no need to call scanner.close(), since the source is a String
	}
	

	public static void log(Object aObject){
		System.out.println(String.valueOf(aObject));
	}
	
	public static void attackFound(String name) {
		System.out.println(name);
	}
	
	public static void main(String[] args) throws IOException{
		
		if (args.length != 2) {
			System.err.println("Wrong number of arguments");
			return;
		}
		try {
			snids s = new snids(args[0],args[1]);
			s.run();
			for (Stream stream: streams)
				stream.searchAttacks();
		}
		catch(Exception e) {
			return;
		}
	}
	
	public class IDSListener implements PacketListener{

		@Override
		public void packetArrived(net.sourceforge.jpcap.net.Packet packet) {
			// Launch filters
			filterPacket(packet);
		}

	}
	
}
