import dpkt
# Mapping số protocol sang tên (IP protocol numbers)
PROTOCOL_MAP = {
    dpkt.ip.IP_PROTO_IP: "IP",
    dpkt.ip.IP_PROTO_ICMP: "ICMP",
    dpkt.ip.IP_PROTO_IGMP: "IGMP",
    dpkt.ip.IP_PROTO_TCP: "TCP",
    dpkt.ip.IP_PROTO_UDP: "UDP",
    dpkt.ip.IP_PROTO_RSVP: "RSVP",
    dpkt.ip.IP_PROTO_GRE: "GRE",
    dpkt.ip.IP_PROTO_ESP: "ESP",
    dpkt.ip.IP_PROTO_AH: "AH",
    dpkt.ip.IP_PROTO_PIM: "PIM",
    dpkt.ip.IP_PROTO_SCTP: "SCTP",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP"
}
        
# Ethernet type mapping
ETHERNET_TYPES = {
    dpkt.ethernet.ETH_TYPE_IP: "IPv4",
    dpkt.ethernet.ETH_TYPE_ARP: "ARP",
    dpkt.ethernet.ETH_TYPE_PPP: "PPP",
    dpkt.ethernet.ETH_TYPE_REVARP: "RARP",
    dpkt.ethernet.ETH_TYPE_8021Q: "802.1Q",
    0x0842: "Wake-on-LAN",
    0x22F3: "TRILL",
    0x8100: "VLAN",
    0x88A8: "802.1ad"
}
        
# Port Mapping
PORT_MAP = {
    # Web
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    # Email
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP-Sub",
    993: "IMAPS",
    995: "POP3S",
    # File Transfer
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH/SFTP",
    69: "TFTP",
    # Name Services
    53: "DNS",
    5353: "mDNS",
    # Authentication
    88: "Kerberos",
    389: "LDAP",
    636: "LDAPS",
    # Database
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    # Streaming & Media
    554: "RTSP",
    1935: "RTMP",
    # Remote Access
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    # Messaging
    1863: "MSN",
    5222: "XMPP",
    5060: "SIP",
    5061: "SIPS",
    # IoT & SCADA
    1883: "MQTT",
    502: "Modbus",
    # Misc
    123: "NTP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    67: "DHCP-Server",
    68: "DHCP-Client",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    445: "SMB",
    500: "IKE",
    514: "Syslog",
    520: "RIP",
    1701: "L2TP",
    1723: "PPTP",
    1812: "RADIUS",
    1900: "SSDP",
    5353: "mDNS"
}