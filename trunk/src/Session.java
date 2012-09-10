import java.util.ArrayList;


public class Session {

	public String remote_ip;
	public int local_port, remote_port;
		
	public ArrayList<Integer> rules_status = new ArrayList<Integer>();

	public boolean fin = false;
	public double fin_seq_number = 0;

	public Session(String remote_ip, int local_port, int remote_port) {
		super();
		this.remote_ip = remote_ip;
		this.local_port = local_port;
		this.remote_port = remote_port;
		
		rules_status = new ArrayList<Integer>();
		for (int i=0; i< snids.rules.size(); i++)
			rules_status.add(new Integer(0));
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
		Session other = (Session) obj;
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
