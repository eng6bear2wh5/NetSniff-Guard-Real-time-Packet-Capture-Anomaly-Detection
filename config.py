# Cấu hình mặc định
DEFAULT_INTERFACE = "wlp45s0"
DEFAULT_OUTPUT_DIR = "./captures"
DEFAULT_MODEL_PATH = "./model/anomaly_model.pkl"
MAX_PCAP_SIZE = 100 * 1024 * 1024  # 100MB

# Tùy chọn hiển thị
TABLE_UPDATE_INTERVAL = 5  # Cập nhật bảng sau mỗi 5 gói tin
MODEL_UPDATE_INTERVAL = 100  # Cập nhật mô hình sau mỗi 100 gói tin
FLOW_ALERT_THRESHOLD = 5  # Ngưỡng cảnh báo luồng bất thường