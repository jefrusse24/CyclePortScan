package util.portscan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Date;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.JTextArea;


/**
 * This class is is responsible for performing port scans on specified ip
 * address range. It will scan a specified set of ports. When this reports the
 * results to a passed in JTextField, it has the capability to do a lookup of
 * the hostname in the IPAddressTracker (ssu-test) database.
 * 
 * @author jefrusse@yahoo.com
 * @since May 3, 2013
 * 
 */
public class Scanner extends Thread {

	private static final int MAXTHREADS =300;
	
	String startingIp;
	String endingIp;
	String dbHostname;	// host name of the db to use for db lookup (if useIpAddrDb is true).
	JTextArea jOutput;
	int portGroup;
	boolean doStop = false;
	boolean useIpAddrDb = false;	// Flag to indicate if we should use the DB for hostname lookup.

	// List of ports for quickPort Testing
	int[] quickPortList = { 21, 22, 23, 25, 49, 53, 67, 69, 79, 80, 110, 113, 119, 123, 135, 139, 143, 161, 389, 443, 445, 514, 1024, 3389, 5000, 5900, 8080 };
	private int maxServicePort = 0;
	
	// The list of ports to be tested during the portscan.
	Vector<Integer> ports;

	/**
	 * Initialize this class with the starting and ending ip addresses. Specify
	 * the ip addresses in dotted decimal notation ie "10.86.152.12".
	 * 
	 * @param start
	 * @param end
	 */
	public Scanner(String start, String end) {
		startingIp = start;
		endingIp = end;
		portGroup = 0;
		ports = new Vector<Integer>();
	}

	/**
	 * Instruct this class to use the database lookup for the addresses.
	 * 
	 * @param useIt
	 */
	public void useIpAddressDatabase(boolean useIt) {
		useIpAddrDb = useIt;
	}

	public void setDbHostname(String dbHost) {
		dbHostname = dbHost;
	}
	
	/**
	 * Instruct this class to stop processing the portscan request. This may let
	 * the currently in-process host finish it's scan.
	 */
	public void stopMe() {
		doStop = true;
		jOutput.append("Stopping Scan.\n");
	}

	/**
	 * Set the maximum service port number.
	 * @param port
	 */
	public void setMaxServicePort(int port) {
		maxServicePort = port;
	}
	
	/**
	 * This will specify the destination for this classes output.
	 * 
	 * @param logOutput
	 */
	public void setOutput(JTextArea logOutput) {
		jOutput = logOutput;
	}

	/**
	 * Set the port groups to scan. Port Group 1 = quick ports. Port Group 2 =
	 * service ports.
	 * 
	 * @param pg
	 */
	public void setPortsGroup(int pg) {
		portGroup = pg;
	}
	
	private void initPortGroup() {

		ports.clear();

		if (portGroup == 1) {
			for (int i = 0; i < quickPortList.length; i++)
				ports.add(quickPortList[i]);
		}

		if (portGroup == 2) {
			for (int i = 0; i < maxServicePort; i++)
				ports.add(i);
		}
	}

	/**
	 * This will perform the portscan. This sends the output to a jOutput object
	 * (JTextArea). It will first attempt an ICMP message to the device. If that
	 * fails, it will attempt to reach the device using a port specified in the
	 * port list.
	 */
	@Override
	public void run() {
		
		initPortGroup();
		initAddress();
		doStop = false;
		String icmpExtra = "";
		String portExtra = "";
		
		try {
			String currentAddress = getNextAddress();
			jOutput.append("+--------------START-------------+\n");
			jOutput.append("Cycling Port Scan\n");
			jOutput.append("Starting address: " + startingIp + "\n");
			jOutput.append("Ending address: " + endingIp + "\n");
			if (portGroup == 2)
				jOutput.append("Ports : 0 - " + maxServicePort + "\n");
			else
				jOutput.append("Ports: " + ports.toString() + "\n");
			jOutput.append("Start " + (new Date()) + "\n\n");

			while ((!doStop) && (currentAddress != null)) {

				String hostname = getHostname(currentAddress);
				boolean icmp = checkIcmp(currentAddress);

//				if (icmp) {
//					jOutput.append(hostname + " Alive. (ICMP)\n");
//					currentAddress = getNextAddress();
//					continue;
//				}

				Vector<Integer> alive = testAddress(currentAddress);
				if (alive.isEmpty() && (! icmp)) {
					jOutput.append(hostname + "  Dead.\n");
				} else {
					icmpExtra = "";
					if (icmp) icmpExtra = " ICMP";
					portExtra = "";
					if (! alive.isEmpty()) portExtra = " Ports "+alive.toString();
					jOutput.append(hostname + "  Alive. "+icmpExtra + portExtra + "\n");
				}
				currentAddress = getNextAddress();
			}

			jOutput.append("Complete. " + (new Date()) + "\n");
			jOutput.append("+---------------END--------------+\n\n");

		} catch (Exception e) {
			jOutput.append("Scanning stopped.\n");
		}

		closeDbConnection();

	}

	// Use for the address loop.
	private String _currentAddress;

	/**
	 * Initalize the address loop.
	 */
	private void initAddress() {
		_currentAddress = null;

	}

	/**
	 * This will get the next address after the value specified by
	 * _currentAddress. If the _currentAddress is null, then it will return the
	 * first address. When the last address is reached, it will set the
	 * _currentAddress to an empty string (not null), which will cause this
	 * method to return a null - indicating we have exhausted the list of
	 * addresses.
	 * 
	 * @return
	 */
	private String getNextAddress() {

		if (_currentAddress == null) {
			if (startingIp.equals(endingIp))
				_currentAddress = "";
			else
				_currentAddress = startingIp;
			return startingIp;
		}
		
		String[] parts = _currentAddress.split("\\.");

		if (parts.length != 4)
			return null;

		int d = Integer.valueOf(parts[3]);
		String nextAddr = null;
		if (d == 255) {
			int c = Integer.valueOf(parts[2]);
			int b = Integer.valueOf(parts[1]);
			int a = Integer.valueOf(parts[0]);
			if (c == 255) {
				if (b == 255) {
					nextAddr = "" + (a + 1) + ".0.0.0";
				} else {
					nextAddr = parts[0] + "." + (b + 1) + ".0.0";
				}
			} else {
				nextAddr = parts[0] + "." + parts[1] + "." + (c + 1) + ".0";
			}
		} else {
			nextAddr = parts[0] + "." + parts[1] + "." + parts[2] + "." + (d + 1);
		}

		if (nextAddr.compareTo(endingIp) == 0) {
			_currentAddress = "";
			return endingIp;

		}

		_currentAddress = nextAddr;
		return nextAddr;
	}

	/**
	 * Test the specified address for response from any of the ports.
	 * 
	 * @param currentAddress
	 * @return
	 */
	private Vector<Integer> testAddress(String address) {

		ExecutorService executor = Executors.newFixedThreadPool(MAXTHREADS);
		Vector<CheckPort> cpt = new Vector<CheckPort>();
		for (Integer i : ports) {
			CheckPort cp = new CheckPort(address, i);
			cpt.add(cp);
			executor.execute(cp);
		}

		// Shutdown all tasks when they are finished.
		executor.shutdown();
		// Wait until all threads are finish
		while (!executor.isTerminated()) {
		}

		Vector<Integer> alivePorts = new Vector<Integer>();
		for (CheckPort cp : cpt) {
			if (cp.portAlive()) {
				alivePorts.add(cp.getPort());
			}
		}

		return alivePorts;

	}

	/**
	 * This will attempt to do an ICMP reachable request to the specified ip
	 * address. If it can reach the address, it will return true.
	 * 
	 * @param ip
	 * @return
	 */
	private boolean checkIcmp(String ip) {
		try {
			if (InetAddress.getByName(ip).isReachable(300))
				return true;
			else
				return false;
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return false;

	}

	/* *******************************************
	 * 
	 * 
	 * 
	 * Database Lookup Section
	 * 
	 * 
	 * 
	 * *******************************************
	 */
	private static Connection connection = null;
	public static final String DEFAULT_DBHOST = "trustsec-svc.cisco.com";
	private static final String DATABASE = "IPAddresses";
	private static final String DBUSER = "trustsecauto";
	private static final String DBPASS = "npfUser";

	/**
	 * This will perform a lookup of the specified ip address. The ip address is
	 * expected to be in dotted decimal notation. ie. "10.86.237.62". If we are
	 * to use the database lookup, it will return the output like
	 * "ip_address - hostname (owner)". Otherwise, it will return
	 * "ip_address".
	 * 
	 * @param ipaddr
	 * @return
	 * @throws Exception
	 */
	private String getHostname(String ipaddr) throws Exception {
		if (!useIpAddrDb)
			return ipaddr;

		if (dbHostname == null)
			return ipaddr;
		
		// Look up the hostname in the database.
		String parts[] = ipaddr.split("\\.");
		String fadr = String.format("%03d.%03d.%03d.%03d", Integer.valueOf(parts[0]), Integer.valueOf(parts[1]),
				Integer.valueOf(parts[2]), Integer.valueOf(parts[3]));
		String query = "select machine, username from Addresses,Users where address=\"" + fadr
				+ "\" and Addresses.uid=Users.uid ";
		String rval = ipaddr;
		try {

			PreparedStatement pstmt = getDBConnection().prepareStatement(query);
			pstmt.execute();
			ResultSet rs = pstmt.getResultSet();

			// Get all entries in this PDU group
			if (rs.next()) {
				rval = ipaddr + " - " + String.format("%-18s (%-11s)", rs.getString(1), rs.getString(2));
			}

			rs.close();
			pstmt.close();

		} catch (Exception e) {
		}

		return rval;
	}

	/**
	 * Gets the shared connection to the DB
	 */
	protected synchronized Connection getDBConnection() {
		if (connection == null) {
			try {
				Class.forName("com.mysql.jdbc.Driver");
				String dbInfo = "jdbc:mysql://" + dbHostname + ":3306/" + DATABASE;
				connection = DriverManager.getConnection(dbInfo, DBUSER, DBPASS);
			} catch (Exception e) {
				useIpAddrDb = false;
				System.err.println("PortScan: Can not connect to database.");
			}
		}
		return connection;
	}

	/**
	 * Close the database connection
	 */
	private void closeDbConnection() {
		if (connection != null) {
			try {
				connection.close();
				connection = null;
			} catch (Exception e) {

			}
		}
	}

}
