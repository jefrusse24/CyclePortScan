package util.portscan;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;


/**
 * This Program will bring up a GUI which allows the user to specify parameters
 * for a port scan. The user can then click on the "Start" button and the
 * program will perform the portscan with the specified parameters.
 * 
 * Version 1.0
 * Date: May 3, 2013
 * 
 * ----------------------------------------------------------------------------
 * Version 1.1
 * Date Sept 5, 2013
 * 
 * Remove hard coded IP Address for DB lookup.  Now you can enter the address.
 * ----------------------------------------------------------------------------
 * 
 * @author jefrusse@yahoo.com
 * @since May 3, 2013
 * 
 */
@SuppressWarnings("serial")
public class PortScan extends JFrame implements ActionListener, HyperlinkListener {

	public static String VERSION = "1.1";
	
	JTabbedPane tabbedPane;
	JComponent panel2;

	private JTextField fStartIp;
	private JTextField fEndIp;
	private JTextField fServicePort;
	private JTextField fDbName;
	private JRadioButton bQuickPorts;
	private JRadioButton bServicePorts;
	private JCheckBox bUseDb;

	private JButton bSTART;
	private JButton bSTOP;
	private JButton bQUIT;

	private static JTextArea logOutput = null;

	private Scanner runner;
	
	private final String startingIp = "192.168.1.1";
	private final String endingIp = "192.168.1.127";

	public static void main(String[] args) throws Exception {

		
		PortScan dd = new PortScan();
		dd.setVisible(true);
		dd.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}

	/**
	 * Create the GUI for this program.
	 */
	public PortScan() {
		super();
		super.setTitle("Cycle Port Scan");
		super.setSize(600, 600);
		super.setLocationRelativeTo(null);
		

	}

	/**
	 * Create the root pane for this program. The root pane consists of a tabbed
	 * pane. One tab for the configuration and one tab for the output.
	 */
	protected JRootPane createRootPane() {

		JRootPane rp = super.createRootPane();
		rp.setLayout(new BorderLayout());
		rp.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

		tabbedPane = new JTabbedPane();
		JComponent panel1 = new JPanel(false);
		createComponents(panel1);
		tabbedPane.addTab("Configuration", panel1);

		panel2 = new JPanel(false);
		createOutput(panel2);
		tabbedPane.addTab("Output", panel2);

		JPanel about = new JPanel(false);
		createAbout(about);
		tabbedPane.addTab("About", about);

		rp.add(tabbedPane);

		return rp;

	}

	/**
	 * This will handle the commands when a button is clicked.
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getActionCommand().equals("Quit")) {
			System.exit(0);
		} else if (e.getActionCommand().equals("Clear")) {
			logOutput.setText("");
		} else if (e.getActionCommand().equals("Start")) {
			startPortScan();
		} else if (e.getActionCommand().equals("Stop")) {
			stopPortScan();
		}
	}

	/**
	 * This will create the configuration GUI. It will attach all of the
	 * configuration GUI objects to the passed in JComponent.
	 * 
	 * @param rp
	 */
	private void createComponents(JComponent rp) {
		JPanel panel = new JPanel(true);
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

		addField(panel, fStartIp = new JTextField(startingIp), "Starting IP Address");
		addField(panel, fEndIp = new JTextField(endingIp), "Ending IP Address");

		bQuickPorts = new JRadioButton("Quick Check");
		bQuickPorts.setSelected(true);
		JPanel sPorts = new JPanel(true);
		bServicePorts = new JRadioButton("Ports up to ");
		sPorts.setLayout(new FlowLayout());
		sPorts.add(bServicePorts);
		fServicePort = new JTextField("5000");
//		fServicePort.setSize(100, 20);
		fServicePort.setPreferredSize(new Dimension(100,20));
		sPorts.add(fServicePort);
		ButtonGroup group = new ButtonGroup();
		group.add(bQuickPorts);
		group.add(bServicePorts);

		JPanel ports = new JPanel(true);
		ports.setLayout(new FlowLayout());
		ports.add(bQuickPorts);
		ports.add(sPorts);
		addField(panel, ports, "Ports");

		JPanel dbPanel = new JPanel(true);
		dbPanel.setLayout(new FlowLayout());
		
		bUseDb = new JCheckBox("Lookup in db ");
		fDbName = new JTextField(Scanner.DEFAULT_DBHOST);
		fDbName.setPreferredSize(new Dimension(200,20));
		dbPanel.add(bUseDb);
		dbPanel.add(fDbName);
		addField(panel, dbPanel, "Lookup in db");

		JPanel buttons = new JPanel(true);
		buttons.setLayout(new FlowLayout());
		buttons.add(bSTART = new JButton("Start"));
		bSTART.addActionListener(this);
		buttons.add(bSTOP = new JButton("Stop"));
		bSTOP.addActionListener(this);
		buttons.add(bQUIT = new JButton("Quit"));
		bQUIT.addActionListener(this);
		panel.add(buttons);

		rp.add(panel, BorderLayout.NORTH);
//		rp.add(new JPanel(), BorderLayout.CENTER);

	}

	/**
	 * This will create the output GUI. All of these GUI objects are attached to
	 * the the passed in JComponent. These are all part of the Output tab of the
	 * main GUI.
	 * 
	 * @param panel2
	 */
	private void createOutput(JComponent panel2) {
		panel2.setLayout(new BoxLayout(panel2, BoxLayout.Y_AXIS));
		logOutput = new JTextArea(20, 20);
		logOutput.setEditable(false);
		Font font = new Font("Monaco", Font.PLAIN, 12);
		logOutput.setFont(font);

		JScrollPane scrollPane = new JScrollPane(logOutput);
		setPreferredSize(new Dimension(450, 110));
		panel2.add(scrollPane, BorderLayout.CENTER);
		
		// Buttons
		JPanel buttons = new JPanel(true);
		buttons.setSize(new Dimension(400, 30));
		buttons.setMaximumSize(new Dimension(400, 30));
		buttons.setLayout(new FlowLayout());

		JButton jb = new JButton("Start");
		jb.addActionListener(this);
		buttons.add(jb);

		jb = new JButton("Stop");
		jb.addActionListener(this);
		buttons.add(jb);

		jb = new JButton("Clear");
		jb.addActionListener(this);
		buttons.add(jb);

		jb = new JButton("Quit");
		jb.addActionListener(this);
		buttons.add(jb);

		panel2.add(buttons);
	}

	private void createAbout(JPanel about) {
		about.setLayout(new BoxLayout(about, BoxLayout.Y_AXIS));

		JEditorPane m_scrollArea = new JEditorPane();
		m_scrollArea.setEnabled(true);
		m_scrollArea.setEditable(false);
		m_scrollArea.addHyperlinkListener(this);
		
		m_scrollArea.setContentType("text/html");
		String text = "<HTML><BODY><H1><FONT COLOR=BLUE>Cycle Port Scan</FONT></H1>";
		text += "Version "+VERSION+"<BR><BR>";
		text += "This program is intended to locate unused IP addresses.  To accomplish this we send an ICMP (ping) message to the specified IP addresses, as well as sending a request to specific ports.<BR><BR>";
		text += "<H2><U>Configuration</U></H2>";
		text += "<B>IP Addresses</B><BR>";
		text += "Starting IP Address - Specify the starting IP address in dotted decimal notation.<BR>";
		text += "Ending IP Address - Specify the ending IP address in dotted decimal notation.<BR><BR>";

		text += "<B>Ports</B><BR>";
		text += "Quick Check - This will check a subset of well known ports to see if any of the ports are open.  See below for the list of ports.<BR>";
		text += "Ports Up To - Will check ports from 0 up to the parameter specified.<BR><BR>";

		text += "<B>Lookup in db</B><BR>";
		text += "Look up in ssu-test db - This is a custom feature that attempts to connect to a database on ssu-test to perform host lookup and owner information.<BR><BR>";

		text += "<H2><U>Output</U></H2>";
		text += "To see the output from the tool, click on the Output tab.  All of the output is displayed on this tab.<BR><BR>";

		text += "<H2><U>About</U></H2>";
		text += "<B>Comments/Suggestions?</B><BR>";
		text += "Please send any comments or suggestions to <A HREF=MAILTO:jefrusse@yahoo.com>jefrusse@yahoo.com</A><BR><BR>";

		text += "Version 1.0 - May 3, 2013<BR><BR>";

		text += "<B>List of Quick Check Ports</B><BR>";
		text += "0 null<BR>21 FTP<BR>22 SSH<BR>";
		text += "23 Telnet<BR>25 SMTP<BR>";
		text += "49 TACACS<BR>53 DNS<BR>67 BOOTP<BR>";
		text += "69 TFTP<BR>79 Finger<BR>80 HTTP<BR>";
		text += "110 POP3<BR>113 IDENT<BR>119 NNTP<BR>123 NTP<BR>135 RPC<BR>139 NetBIOS<BR>143 IMAP<BR>161 SNMP<BR>";
		text += "389 LDAP<BR>443 HTTPS<BR>445 MSFT AD<BR>514 SYSLOG<BR>1002 ms-ils<BR>1024 DCOM<BR>1025 Host<BR>";
		text += "1026 Host<BR>1027 Host<BR>1028 Host<BR>1029 Host<BR>1030 Host<BR>1720 H.323<BR>";
		text += "3389 RDP<BR>5000 UPnP<BR>5900 VNC<BR>8080 HTTPS";

		m_scrollArea.setText(text);
		
		JScrollPane m_scrollPane = new JScrollPane(m_scrollArea,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		m_scrollPane.setOpaque(false);
		m_scrollPane.setVisible(true);

		about.add(m_scrollPane);
		
	}

	/**
	 * This will create a new panel with the specified name. In this panel will
	 * go the passed in JComponent. This new panel will be added to the passed
	 * in panel.
	 * 
	 * @param panel
	 * @param field
	 * @param name
	 */
	private void addField(JPanel panel, JComponent field, String name) {
		JPanel inner = new JPanel(true);
		inner.setLayout(new BorderLayout());
		inner.setBorder(BorderFactory.createTitledBorder(name));
		inner.add(field, BorderLayout.CENTER);
		panel.add(inner);
	}

	/**
	 * This is called when the use clicks the "Start" button. This is
	 * responsible for calling the Scanner thread and starting the test. It will
	 * pass all of the applicable parameters to the Scanner class.
	 */
	private void startPortScan() {		
		if (! validateInputs())
			return;
		
		if (runner != null) {
			if (runner.isAlive()) {
				return;
			}
		}
		runner = new Scanner(fStartIp.getText(), fEndIp.getText());
		runner.setMaxServicePort(Integer.valueOf(fServicePort.getText()));
		
		if (bQuickPorts.isSelected())
			runner.setPortsGroup(1);
		if (bServicePorts.isSelected())
			runner.setPortsGroup(2);

		runner.useIpAddressDatabase(bUseDb.isSelected());
		runner.setDbHostname(fDbName.getText());
		runner.setOutput(logOutput);
		runner.start();

	}

	/**
	 * Validate all of the parameters that a user can specify.
	 * @return
	 */
	private boolean validateInputs() {
		if (! validateIp(fStartIp.getText(),"Starting IP Address Needs to be in the format of N.N.N.N"))
			return false;
		if (! validateIp(fEndIp.getText(),"Ending IP Address Needs to be in the format of N.N.N.N"))
			return false;
		if (! validateNumber(fServicePort.getText(),"Service Port has to be an integer."))
			return false;
		if (! validateaddrRange(fStartIp,fEndIp))
			return false;
		
		return true;
	}

	/**
	 * Make sure the the value at v1 is less than the value at v2.
	 * This will also remove any leading 0's in the numbers.
	 * @param v1
	 * @param v2
	 * @return
	 */
	private boolean validateaddrRange(JTextField v1, JTextField v2) {
		String vt1 = v1.getText();
		String vt2 = v2.getText();
		String[] parts = vt1.split("\\.");
		long a = Integer.valueOf(parts[0]);
		long b = Integer.valueOf(parts[1]);
		long c = Integer.valueOf(parts[2]);
		long d = Integer.valueOf(parts[3]);
		v1.setText(""+a+"."+b+"."+c+"."+d);
		long addr1 = a << 24 | b << 16 | c << 8 | d;

		parts = vt2.split("\\.");
		a = Integer.valueOf(parts[0]);
		b = Integer.valueOf(parts[1]);
		c = Integer.valueOf(parts[2]);
		d = Integer.valueOf(parts[3]);
		v2.setText(""+a+"."+b+"."+c+"."+d);
		long addr2 = a << 24 | b << 16 | c << 8 | d;
		if (addr1 > addr2) {
			JOptionPane.showMessageDialog(null, "Starting address needs to be before ending address.");
			return false;
		}
		
		return true;
		
	}

	/**
	 * This will validate the number is in dotted decimal notation.
	 * 
	 * @param text
	 * @param message
	 * @return
	 */
	private boolean validateIp(String text, String message) {
		try {
			String[] parts = text.split("\\.");
			if (parts.length != 4) {
				JOptionPane.showMessageDialog(null, message);
				return false;
			}
			int a = Integer.valueOf(parts[0]);
			int b = Integer.valueOf(parts[1]);
			int c = Integer.valueOf(parts[2]);
			int d = Integer.valueOf(parts[3]);
			if ((a < 0) || (a > 255) || (b < 0) || (b > 255) || (c < 0) || (c > 255) || (d < 0) || (d > 255)) {
				JOptionPane.showMessageDialog(null, message);
				return false;
			}
		} catch (NumberFormatException e) {
			JOptionPane.showMessageDialog(null, message);
			return false;
		}
		return true;
	}

	/**
	 * This will validate that the number is a positive integer.
	 * @param text
	 * @param message
	 * @return
	 */
	private boolean validateNumber(String text, String message) {
		try {
			int i = Integer.valueOf(text);
			if ((i < 1) || (i > 65535))  {
				JOptionPane.showMessageDialog(null, message);
				return false;
			}
		} catch (NumberFormatException e) {
			JOptionPane.showMessageDialog(null, message);
			return false;
		}
		return true;
	}

	/**
	 * This is called when the user clicks the "Stop" button. It will tell the
	 * thread that the user has requested to stop what it is doing.
	 */
	private void stopPortScan() {
		if (runner != null) {
			runner.stopMe();
		}

	}

	@Override
	public void hyperlinkUpdate(HyperlinkEvent event) {
		if (event.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
			try {
				java.awt.Desktop.getDesktop().browse(event.getURL().toURI());
			} catch(Exception ioe) {
				ioe.printStackTrace();
				// Some warning to user
			}
		}
	}
	
}