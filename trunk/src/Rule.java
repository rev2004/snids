import java.util.ArrayList;
import java.util.Scanner;


public class Rule {

	public String name;
	public String type;
	public String proto;
	public String local_port;
	public String remote_port;
	public String ip;
	
	public ArrayList<String> patterns = new ArrayList<String>();
	public ArrayList<String> patterns_types = new ArrayList<String>(); // Ex: send,recv,..
	
	ArrayList<Flags> flags = new ArrayList<Flags>(); // for each send/recv, save the flags if any
	
	public Rule(String name) {
		this.name = name;
	}	

	public void print() {
		System.out.println("******New rule******\nName = "+name);
		System.out.println("Type = "+type);
		System.out.println("Proto = "+proto);
		System.out.println("Local port = "+local_port);
		System.out.println("Remote port = "+remote_port);
		System.out.println("IP = "+ip);

		for (int i=0; i<patterns.size(); i++) {
			System.out.print(" - Check = "+patterns.get(i)+ " type = "+ patterns_types.get(i));
		}
						
		System.out.print("\n\n");
	}

}
