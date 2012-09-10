import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jpcap.packet.*;

public class Stream {

	public String remote_ip;
	public int local_port, remote_port;

	double local_seq, remote_seq;
	
	ArrayList<TCPPacket> sends = new ArrayList<TCPPacket>();
	ArrayList<TCPPacket> recvs = new ArrayList<TCPPacket>();

	public boolean fin = false;
	public double fin_seq_number = 0;
	
	public Stream(String remote_ip, int local_port, int remote_port) {
		super();
		this.remote_ip = remote_ip;
		this.local_port = local_port;
		this.remote_port = remote_port;
	}
	
	// Add a tcp packet and set current seq num
	public void addPacket(TCPPacket p) {
		
		if(p.src_ip.getHostAddress().equalsIgnoreCase(snids.host)) {
			sends.add(p);
		}
		else {
			recvs.add(p);
		}
			
	}

	// Check for stream error
	public void searchAttacks() {
		
		TCPPacket[] sends_ordered = new TCPPacket[sends.size()];
		TCPPacket[] recvs_ordered = new TCPPacket[recvs.size()];
		
		for (int i=0; i<sends.size(); i++)
			sends_ordered[i] = sends.get(i);

		for (int i=0; i<recvs.size(); i++)
			recvs_ordered[i] = recvs.get(i);
		
		/** SORT **/
		// Bubblesort on sends
		boolean found = false;
		do {
			found = false;
			for (int i=0; i<sends.size()-1; i++) {
				if (sends_ordered[i].sequence > sends_ordered[i+1].sequence) {
					TCPPacket temp;
					temp = sends_ordered[i];
					sends_ordered[i] = sends_ordered[i+1];
					sends_ordered[i+1] = temp;
					found = true;
				}
			}
		}while(found);
		// Bubblesort on recvs
		found = false;
		do {
			found = false;
			for (int i=0; i<recvs.size()-1; i++) {
				if (recvs_ordered[i].sequence > recvs_ordered[i+1].sequence) {
					TCPPacket temp;
					temp = recvs_ordered[i];
					recvs_ordered[i] = recvs_ordered[i+1];
					recvs_ordered[i+1] = temp;
					found = true;
				}
			}
		}while(found);
		/** END SORT **/	
		
		sends.clear();
		recvs.clear();
		
		/** DATA RECONSTRUCTION **/
		byte[] recv_data = null;
		byte[] send_data = null;

		for (int i=0; i<recvs_ordered.length; i++)
			recv_data = concat(recv_data, recvs_ordered[i].data);
		
		for (int i=0; i<sends_ordered.length; i++)
			send_data = concat(send_data, sends_ordered[i].data);
		
		//System.out.println("");
		//System.out.println("-- Received -- \n"+new String(recv_data,0));
		//System.out.println("");
		//System.out.println("-- Sent -- \n"+new String(send_data,0));
		
		/** CHECK RULES **/
		for (Rule r: snids.rules) {
			if (!r.type.equalsIgnoreCase("stream")) continue; // only stream type

			boolean match = true;
			
			// check remote ip
			if (!r.ip.equalsIgnoreCase("any")) 
				if (!remote_ip.equalsIgnoreCase(r.ip)) 
					match = false;

			// check remote port
			if (!r.remote_port.equalsIgnoreCase("any")) 
				if (remote_port != Integer.parseInt(r.remote_port)) 
					match = false;
			
			// check locale port
			if (!r.local_port.equalsIgnoreCase("any")) 
				if (local_port != Integer.parseInt(r.local_port)) 
					match = false;
			
			if (!match) continue;
			
			//System.out.println(r.name);

			// check send and received data
			String type = r.patterns_types.get(0);
			if (type.equalsIgnoreCase("send")) { // check in send data
				boolean match_2 = false;
//				System.out.println("** Check "+r.patterns.get(0));
				Pattern regex = Pattern.compile(r.patterns.get(0), Pattern.DOTALL);
				String candidateString = new String(send_data,0);
				Matcher matcher = regex.matcher(candidateString);	
				while (matcher.find()) {
					match_2 = true;
				}
				if (match_2)
					snids.attackFound(r.name);
			}
			else {
				boolean match_2 = false;
				Pattern regex = Pattern.compile(r.patterns.get(0), Pattern.DOTALL);
				String candidateString = new String(recv_data,0);
				Matcher matcher = regex.matcher(candidateString);	
				while (matcher.find()) {
					match_2 = true;
				}
				if (match_2)
					snids.attackFound(r.name);
			}
			
		}
		
	}

	// source : http://stackoverflow.com/questions/80476/how-to-concatenate-two-arrays-in-java
	public byte[] concat(byte[] A, byte[] B) {
		
		if(A == null) {		
			if(B == null) return new byte[0];
			else return B;
		}
		
		byte[] C= new byte[A.length+B.length];
		System.arraycopy(A, 0, C, 0, A.length);
		System.arraycopy(B, 0, C, A.length, B.length);
		return C;
	}

	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + local_port;
		result = prime * result
				+ ((remote_ip == null) ? 0 : remote_ip.hashCode());
		result = prime * result + remote_port;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Stream other = (Stream) obj;
		if (local_port != other.local_port)
			return false;
		if (remote_ip == null) {
			if (other.remote_ip != null)
				return false;
		} else if (!remote_ip.equals(other.remote_ip))
			return false;
		if (remote_port != other.remote_port)
			return false;
		return true;
	}
	
	
	
}
