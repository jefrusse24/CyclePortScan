package util.portscan;

import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * A Simple class that will check if a port is open.
 * 
 * @author jefrusse@yahoo.com
 * @since May 3, 2013
 *
 */
public class CheckPort implements Runnable {

	String ip;
	int port;
	boolean alive;
	/**
	 * Specify the ip address and the port to check.
	 * @param addr
	 * @param port
	 */
	public CheckPort(String addr, int port) {
		ip = addr;
		this.port = port;
		alive = false;
	}

	/**
	 * If the port is seen alive, this will return true.
	 * @return
	 */
	public boolean portAlive() {
		return alive;
	}
	
	/**
	 * The port number this class checked.
	 * @return
	 */
	public int getPort() {
		return port;
	}
	
	/**
	 * Do the check.
	 */
	@Override
	public void run() {
		try {
			Socket socket = new Socket();
			socket.connect(new InetSocketAddress(ip, port), 500);
			socket.close();
			alive = true;
		} catch (Exception ex) {
		}
	}

}
