import os
import numpy as np
import joblib
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class EnhancedAnomalyDetection:
    def __init__(self, model_path=None, contamination=0.05):
        self.features = ["packet_size", "protocol_num", "src_port", "dst_port",
                         "time_delta", "packet_count", "bytes_count", "avg_packet_rate"]
        self.scaler = StandardScaler()
        self.contamination = contamination
        
        # Duy trì thống kê luồng dữ liệu
        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "bytes_total": 0,
            "last_seen": 0,
            "intervals": []
        })
        
        # Tải mô hình nếu có sẵn, nếu không tạo mới
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
            print(f"[+] Đã tải mô hình phát hiện bất thường từ {model_path}")
        else:
            self.model = IsolationForest(contamination=contamination, random_state=42)
            self.is_trained = False
            print(f"[+] Đã khởi tạo mô hình phát hiện bất thường mới")
    
    def _load_model(self, model_path):
        """Tải mô hình đã huấn luyện"""
        try:
            loaded_data = joblib.load(model_path)
            self.model = loaded_data["model"]
            self.scaler = loaded_data["scaler"]
            self.is_trained = True
        except Exception as e:
            print(f"[!] Lỗi khi tải mô hình: {e}")
            self.model = IsolationForest(contamination=self.contamination, random_state=42)
            self.is_trained = False
    
    def save_model(self, model_path="./model/anomaly_model.pkl"):
        """Lưu mô hình đã huấn luyện"""
        if not os.path.exists(os.path.dirname(model_path)):
            os.makedirs(os.path.dirname(model_path))
        
        try:
            joblib.dump({
                "model": self.model,
                "scaler": self.scaler
            }, model_path)
            print(f"[+] Đã lưu mô hình vào {model_path}")
            return True
        except Exception as e:
            print(f"[!] Lỗi khi lưu mô hình: {e}")
            return False
    
    def extract_features(self, packet_info, timestamp):
        """Trích xuất đặc trưng từ gói tin và luồng gói tin"""
        if packet_info['protocol'] in ["TCP", "UDP"]:
            flow_key = (
                packet_info["src_ip"], 
                packet_info["src_port"],
                packet_info["dst_ip"], 
                packet_info["dst_port"],
                packet_info["protocol"]
            )
        else:
            flow_key = (
                packet_info["src_ip"], 
                packet_info["dst_ip"], 
                packet_info["protocol"]
            )
        
        # Cập nhật lại hệ thống luồng
        flow = self.flow_stats[flow_key]

        # Tính thời gian giữa các gói tin trong cùng 1 luồng
        time_delta = 0
        if flow["last_seen"] > 0:
            time_delta = timestamp - flow["last_seen"]
            flow["intervals"].append(time_delta)
            if len(flow["intervals"]) > 50:
                flow["intervals"] = flow["intervals"][-50:]

        # Cập nhật thống kê
        flow["packet_count"] += 1
        flow["bytes_total"] += packet_info["size"]
        flow["last_seen"] = timestamp

        # Xác định số protocol
        protocol_map = {
            "TCP": 6, "UDP": 17, "ICMP": 1, "HTTP": 80, "HTTPS": 443, 
            "DNS": 53, "ARP": 0, "IPv4": 4, "IPv6": 6
        }
        protocol_num = protocol_map.get(packet_info["protocol"], 0)

        # Tính tốc độ trung bình gói tin
        avg_packet_rate = 0
        if len(flow["intervals"]) > 0:
                avg_interval = sum(flow["intervals"]) / len(flow["intervals"])
                if avg_interval > 0:  # Thêm kiểm tra này để tránh chia cho 0
                    avg_packet_rate = 1.0 / avg_interval

        # Xử lý giá trị cổng
        try:
            src_port = int(packet_info["src_port"]) if packet_info["src_port"] != "N/A" else 0
        except:
            src_port = 0

        try:
            dst_port = int(packet_info["dst_port"]) if packet_info["dst_port"] != "N/A" else 0
        except:
            dst_port = 0

        # Tạo vector đặc trưng
        features = [
            packet_info["size"],              # Kích thước gói tin
            protocol_num,                     # Mã giao thức
            src_port,                         # Cổng nguồn (đã xử lý an toàn)
            dst_port,                         # Cổng đích (đã xử lý an toàn)
            time_delta,                       # Thời gian giữa các gói
            flow["packet_count"],             # Số gói tin trong luồng
            flow["bytes_total"],              # Tổng số byte trong luồng
            avg_packet_rate                   # Tốc độ gói tin
        ]

        return np.array(features), flow_key

    def fit(self, feature_vectors):
        """Huấn luyện mô hình với dữ liệu mới"""
        if len(feature_vectors) < 10:
            print("[!] Không đủ dữ liệu để huấn luyện mô hình")
            return False
        try:
            # Chuẩn hóa dữ liệu
            X = self.scaler.fit_transform(feature_vectors)

            # Huấn luyện mô hình
            self.model.fit(X)
            self.is_trained = True

            return True
        except Exception as e:
            print(f"[!] Lỗi khi huấn luyện mô hình: {e}")
            return False
    
    def predict(self, feature_vector):
        """Dự đoán gói tin có bất thường hay không"""
        if not self.is_trained:
            return 0, 0  # Chưa huấn luyện, không phát hiện được bất thường
        
        try:
            # Chuẩn hóa dữ liệu
            X = self.scaler.transform([feature_vector])
            # Dự đoán (-1: bất thường, 1: bình thường)
            result = self.model.predict(X)[0]
            
            # Tính điểm bất thường
            score = self.model.decision_function(X)[0]
            
            return result, score
        except Exception as e:
            print(f"[!] Lỗi khi dự đoán: {e}")
            return 0, 0
