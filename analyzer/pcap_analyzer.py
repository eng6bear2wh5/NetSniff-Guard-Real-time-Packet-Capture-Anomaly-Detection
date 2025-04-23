from rich.console import Console
from rich.table import Table
from rich.text import Text
import dpkt
import os
from datetime import datetime
from collections import defaultdict
from analyzer.packet_sniffer import PacketSniffer
from utils.packet_parser import PacketParser
from models.anomaly_detector import EnhancedAnomalyDetection

def analyze_pcap_file(pcap_file, model_path="./model/anomaly_model.pkl"):
    """Phân tích file PCAP đã lưu"""
    print(f"[+] Bắt đầu phân tích file PCAP: {pcap_file}")
    
    # Khởi tạo detector
    detector = EnhancedAnomalyDetection(model_path=model_path)
    
    # Khởi tạo bảng hiển thị
    console = Console()
    table = Table(title=f"[~] Phân tích file PCAP: {os.path.basename(pcap_file)}")
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Timestamp", width=12)
    table.add_column("Src IP", width=15)
    table.add_column("Dest IP", width=15)
    table.add_column("Proto", width=10)
    table.add_column("App Proto", width=10)
    table.add_column("Details", width=20)
    table.add_column("Size", style="cyan", width=6)
    table.add_column("Anomaly", style="red", width=8)
    
    # Mở file PCAP
    try:
        with open(pcap_file, 'rb') as f:
            pcap_reader = dpkt.pcap.Reader(f)
            
            packet_id = 0
            anomaly_count = 0
            feature_vectors = []
            flow_anomalies = defaultdict(int)
            
            # Tạo đối tượng PacketSniffer tạm thời để sử dụng phương thức parse_packet
            temp_sniffer = PacketSniffer(interface="none")
            
            # Đọc từng gói tin
            for timestamp, packet in pcap_reader:
                packet_id += 1
                
                # Phân tích gói tin
                packet_info = temp_sniffer.parse_packet(packet)
                
                # Trích xuất đặc trưng
                features, flow_key = detector.extract_features(packet_info, timestamp)
                feature_vectors.append(features)
                
                # Phát hiện bất thường
                is_anomaly, score = detector.predict(features)
                
                # Cập nhật thống kê bất thường theo luồng
                if is_anomaly == -1:
                    anomaly_count += 1
                    flow_anomalies[flow_key] += 1
                
                # Chuẩn bị dữ liệu hiển thị
                anomaly_text = "Bình thường"
                anomaly_style = "green"
                if is_anomaly == -1:
                    anomaly_text = f"Bất thường ({score:.2f})"
                    anomaly_style = "red"
                
                # Định dạng timestamp
                time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
                
                # Thêm vào bảng
                table.add_row(
                    str(packet_id),
                    time_str,
                    str(packet_info["src_ip"]),
                    str(packet_info["dst_ip"]),
                    str(packet_info["protocol"]),
                    str(packet_info["app_proto"]),
                    str(packet_info["details"]),
                    str(packet_info["size"]),
                    Text(anomaly_text, style=anomaly_style)
                )
                
                # Cập nhật bảng định kỳ
                if packet_id % 100 == 0:
                    console.clear()
                    console.print(table)
                    console.print(f"Đã phân tích: {packet_id} gói tin, phát hiện: {anomaly_count} bất thường")
                
                # Huấn luyện lại mô hình sau mỗi 1000 gói tin
                if packet_id % 1000 == 0 and len(feature_vectors) > 100:
                    detector.fit(feature_vectors[-1000:])
            
            # Hiển thị kết quả cuối cùng
            console.clear()
            console.print(table)
            
            # Tìm luồng có nhiều bất thường nhất
            top_flows = sorted(flow_anomalies.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Hiển thị thống kê
            print(f"\n[+] Hoàn tất phân tích: {packet_id} gói tin, phát hiện: {anomaly_count} bất thường")
            
            if top_flows:
                print("\n[~] Top 5 luồng có nhiều bất thường nhất:")
                for flow, count in top_flows:
                    if len(flow) == 5:  # TCP/UDP
                        print(f"  - {flow[0]}:{flow[1]} → {flow[2]}:{flow[3]} [{flow[4]}]: {count} bất thường")
                    else:  # Các giao thức khác
                        print(f"  - {flow[0]} → {flow[1]} [{flow[2]}]: {count} bất thường")
            
    except Exception as e:
        print(f"[!] Lỗi khi phân tích file PCAP: {e}")