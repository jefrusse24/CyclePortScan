Cycle Port Scan
Version 1.1

This program is intended to locate unused IP addresses. To accomplish 
this we send an ICMP (ping) message to the specified IP addresses, as
 well as sending a request to specific ports.

Configuration
IP Addresses
Starting IP Address - Specify the starting IP address in dotted decimal
 notation.
Ending IP Address - Specify the ending IP address in dotted decimal 
notation.

Ports
Quick Check - This will check a subset of well known ports to see if any
 of the ports are open. See below for the list of ports.
Ports Up To - Will check ports from 0 up to the parameter specified.

Lookup in db
Look up in ssu-test db - This is a custom feature that attempts to 
connect to a database on ssu-test to perform host lookup and owner 
information.

Output
To see the output from the tool, click on the Output tab. All of the
output is displayed on this tab.

About
Comments/Suggestions?
Please send any comments or suggestions to jefrusse@yahoo.com

Version 1.0 - May 3, 2013

List of Quick Check Ports
0 null
21 FTP
22 SSH
23 Telnet
25 SMTP
49 TACACS
53 DNS
67 BOOTP
69 TFTP
79 Finger
80 HTTP
110 POP3
113 IDENT
119 NNTP
123 NTP
135 RPC
139 NetBIOS
143 IMAP
161 SNMP
389 LDAP
443 HTTPS
445 MSFT AD
514 SYSLOG
1002 ms-ils
1024 DCOM
1025 Host
1026 Host
1027 Host
1028 Host
1029 Host
1030 Host
1720 H.323
3389 RDP
5000 UPnP
5900 VNC
8080 HTTPS