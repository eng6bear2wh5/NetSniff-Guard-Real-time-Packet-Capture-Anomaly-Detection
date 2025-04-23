import socket
import dpkt
from .protocol_maps import PROTOCOL_MAP, ETHERNET_TYPES, PORT_MAP

class PacketParser:
    @staticmethod
    def mac_addr(addr):  # Đã xóa tham số 'self' không cần thiết
        """Chuyển đổi địa chỉ MAC thành định dạng đọc được"""
        return ':'.join('%02x' % b for b in addr)

    @staticmethod
    def parse_packet(packet):
        """Phân tích gói tin và trích xuất thông tin cần thiết"""
        # Khởi tạo giá trị mặc định
        result = {
            "src_ip": "Unknown",
            "dst_ip": "Unknown",
            "protocol": "Unknown",
            "src_port": "N/A",
            "dst_port": "N/A",
            "app_proto": "",
            "details": "",
            "size": len(packet)  # Thêm kích thước gói tin
        }
        
        try:
            # Phân tích Ethernet frame
            eth = dpkt.ethernet.Ethernet(packet)
            
            # Lấy thông tin MAC
            src_mac = PacketParser.mac_addr(eth.src)  # Sửa cách gọi statiscmethod
            dst_mac = PacketParser.mac_addr(eth.dst)  # Sửa cách gọi staticmethod
            
            # Xác định loại Ethernet
            ether_type = eth.type
            eth_type_name = ETHERNET_TYPES.get(ether_type, f"0x{ether_type:04x}")  # Sử dụng ETHERNET_TYPES từ import
            
            # Ghi nhận loại Ethernet
            result["protocol"] = eth_type_name
            result["details"] = f"MAC: {src_mac[:8]}..→{dst_mac[:8]}.."
            
            # Phân tích ARP
            if ether_type == dpkt.ethernet.ETH_TYPE_ARP:
                if isinstance(eth.data, dpkt.arp.ARP):
                    arp = eth.data
                    src_ip = socket.inet_ntoa(arp.spa)
                    dst_ip = socket.inet_ntoa(arp.tpa)
                    result["src_ip"] = src_ip
                    result["dst_ip"] = dst_ip
                    
                    if arp.op == dpkt.arp.ARP_OP_REQUEST:
                        result["details"] = f"Who has {dst_ip}? Tell {src_ip}"
                    elif arp.op == dpkt.arp.ARP_OP_REPLY:
                        result["details"] = f"{src_ip} is at {src_mac}"
            
            # Phân tích IPv4
            elif ether_type == dpkt.ethernet.ETH_TYPE_IP:
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    
                    # Lấy địa chỉ IP nguồn và đích
                    result["src_ip"] = socket.inet_ntoa(ip.src)
                    result["dst_ip"] = socket.inet_ntoa(ip.dst)
                    
                    # Xác định giao thức IP
                    protocol = ip.p
                    result["protocol"] = PROTOCOL_MAP.get(protocol, f"{protocol}")  # Sử dụng PROTOCOL_MAP từ import
                    
                    # Phân tích ICMP
                    if isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp = ip.data
                        icmp_type = icmp.type
                        if icmp_type == 0:
                            result["details"] = "Echo Reply"
                        elif icmp_type == 3:
                            result["details"] = f"Dest Unreachable (code:{icmp.code})"
                        elif icmp_type == 5:
                            result["details"] = "Redirect"
                        elif icmp_type == 8:
                            result["details"] = "Echo Request"
                        elif icmp_type == 11:
                            result["details"] = "Time Exceeded"
                        else:
                            result["details"] = f"Type:{icmp_type}, Code:{icmp.code}"
                    
                    # Phân tích TCP
                    elif isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        result["src_port"] = tcp.sport
                        result["dst_port"] = tcp.dport
                        
                        # Xác định ứng dụng dựa vào cổng
                        src_app = PORT_MAP.get(tcp.sport, "")  # Sử dụng PORT_MAP từ import
                        dst_app = PORT_MAP.get(tcp.dport, "")  # Sử dụng PORT_MAP từ import
                        result["app_proto"] = dst_app or src_app
                        
                        # Phân tích flags
                        flags = []
                        if tcp.flags & dpkt.tcp.TH_FIN:
                            flags.append("FIN")
                        if tcp.flags & dpkt.tcp.TH_SYN:
                            flags.append("SYN")
                        if tcp.flags & dpkt.tcp.TH_RST:
                            flags.append("RST")
                        if tcp.flags & dpkt.tcp.TH_PUSH:
                            flags.append("PSH")
                        if tcp.flags & dpkt.tcp.TH_ACK:
                            flags.append("ACK")
                        if tcp.flags & dpkt.tcp.TH_URG:
                            flags.append("URG")
                        
                        result["details"] = f"Flags: {' '.join(flags)}"
                        
                        # Phân tích dữ liệu ứng dụng
                        if len(tcp.data) > 0:
                            # HTTP
                            if (tcp.dport == 80 or tcp.sport == 80) and not result["app_proto"]:
                                result["app_proto"] = "HTTP"
                                try:
                                    if tcp.data.startswith(b'GET ') or tcp.data.startswith(b'POST ') or tcp.data.startswith(b'HTTP/'):
                                        first_line = tcp.data.split(b'\r\n')[0].decode('utf-8', 'replace')
                                        result["details"] = first_line[:24] + "..." if len(first_line) > 24 else first_line
                                except:
                                    pass
                            
                            # HTTPS
                            elif tcp.dport == 443 or tcp.sport == 443:
                                if not result["app_proto"]:
                                    result["app_proto"] = "HTTPS"
                                # Check for TLS handshake
                                try:
                                    if tcp.data[0] == 0x16:  # TLS Handshake
                                        if tcp.data[1] == 0x03:  # TLS version
                                            result["details"] += " TLS Handshake"
                                except:
                                    pass
                    
                    # Phân tích UDP
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        result["src_port"] = udp.sport
                        result["dst_port"] = udp.dport
                        
                        # Xác định ứng dụng dựa vào cổng
                        src_app = PORT_MAP.get(udp.sport, "")  # Sử dụng PORT_MAP từ import
                        dst_app = PORT_MAP.get(udp.dport, "")  # Sử dụng PORT_MAP từ import
                        result["app_proto"] = dst_app or src_app
                        
                        # Phân tích DNS
                        if udp.sport == 53 or udp.dport == 53:
                            if not result["app_proto"]:
                                result["app_proto"] = "DNS"
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                if dns.qr == dpkt.dns.DNS_Q:
                                    result["details"] = f"Query: {dns.qd[0].name.decode('utf-8', 'replace')}"
                                elif dns.qr == dpkt.dns.DNS_R:
                                    if len(dns.an) > 0:
                                        if dns.an[0].type == dpkt.dns.DNS_A:
                                            ip = socket.inet_ntoa(dns.an[0].rdata)
                                            result["details"] = f"Response: {ip}"
                            except:
                                pass
                        
                        # DHCP
                        elif (udp.sport == 67 and udp.dport == 68) or (udp.sport == 68 and udp.dport == 67):
                            if not result["app_proto"]:
                                result["app_proto"] = "DHCP"
                            try:
                                if len(udp.data) > 240:  # Min DHCP size
                                    msg_type = udp.data[242]
                                    types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 
                                             5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
                                    result["details"] = f"DHCP {types.get(msg_type, 'Unknown')}"
                            except:
                                pass
                        
                        # NTP
                        elif udp.sport == 123 or udp.dport == 123:
                            if not result["app_proto"]:
                                result["app_proto"] = "NTP"
        
        except Exception as e:
            # Xử lý lỗi khi phân tích gói tin
            print(f"[!] Lỗi khi phân tích gói tin: {e}")
        
        return result