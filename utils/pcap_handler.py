import os
import dpkt
from datetime import datetime

class PCAPHandler:
    def __init__(self, output_dir="./captures"):
        self.output_dir = output_dir
        self.pcap_writer = None
        self.current_pcap_file = None
        
        # Tạo thư mục lưu trữ nếu chưa tồn tại
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Mở file pcap để ghi
        self._create_pcap_file()

    def _create_pcap_file(self):
        """Tạo file PCAP mới để ghi dữ liệu"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_pcap_file = os.path.join(self.output_dir, f"capture_{timestamp}.pcap")
        
        try:
            self.pcap_writer = dpkt.pcap.Writer(open(self.current_pcap_file, 'wb'))
            print(f"[+] Đã tạo file PCAP: {self.current_pcap_file}")
        except Exception as e:
            print(f"[!] Lỗi khi tạo file PCAP: {e}")
            self.pcap_writer = None
    
    def save_packet_to_pcap(self, timestamp, packet):
        """Lưu gói tin vào file PCAP"""
        if self.pcap_writer:
            try:
                self.pcap_writer.writepkt(packet, timestamp)
                
                # Tự động tạo file mới khi file hiện tại quá lớn (100MB)
                if os.path.getsize(self.current_pcap_file) > 100 * 1024 * 1024:
                    self.pcap_writer.close()
                    self._create_pcap_file()
                    
            except Exception as e:
                print(f"[!] Lỗi khi lưu gói tin vào PCAP: {e}")

    def close(self):
        """Đóng file PCAP hiện tại"""
        if self.pcap_writer:
            self.pcap_writer.close()
            print(f"[+] Đã đóng file PCAP: {self.current_pcap_file}")
        return None