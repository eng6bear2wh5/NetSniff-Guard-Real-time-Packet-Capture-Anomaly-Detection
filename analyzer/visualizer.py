from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.layout import Layout
from rich import box
import time
from datetime import datetime

class PacketVisualizer:
    def __init__(self, title="[~] Danh sách gói tin bắt được"):
        self.console = Console()
        self.table = self._create_table(title)
        self.packet_count = 0
        self.anomaly_count = 0
        self.start_time = time.time()
        self.suspicious_flows = {}
        self.alerts = []
        
    def _create_table(self, title):
        """Tạo bảng hiển thị"""
        table = Table(title=title)
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Src IP", width=15)
        table.add_column("Dest IP", width=15)
        table.add_column("Proto", width=10)
        table.add_column("Src Port", width=8)
        table.add_column("Dest Port", width=8)
        table.add_column("App Proto", width=10)
        table.add_column("Details", width=25)
        table.add_column("Size", style="cyan", width=6)
        table.add_column("Anomaly", style="red", width=10)
        table.add_column("Flow", style="yellow", width=6)
        return table
    
    def add_packet(self, packet_data, anomaly_info):
        """Thêm gói tin vào bảng hiển thị"""
        self.packet_count += 1
        
        # Trích xuất thông tin phát hiện bất thường
        is_anomaly, anomaly_score, flow_score = anomaly_info
        
        # Định dạng thông tin bất thường
        anomaly_text = "Bình thường"
        anomaly_style = "green"
        if is_anomaly == -1:
            anomaly_text = f"Bất thường ({anomaly_score:.2f})"
            anomaly_style = "red"
            self.anomaly_count += 1
        
        # Định dạng điểm luồng
        flow_style = "green"
        if flow_score > 3:
            flow_style = "yellow"
        if flow_score > 5:
            flow_style = "red"
            
            # Tạo khóa luồng để theo dõi
            if packet_data["protocol"] in ["TCP", "UDP"]:
                flow_key = f"{packet_data['src_ip']}:{packet_data['src_port']} → {packet_data['dst_ip']}:{packet_data['dst_port']} [{packet_data['protocol']}]"
            else:
                flow_key = f"{packet_data['src_ip']} → {packet_data['dst_ip']} [{packet_data['protocol']}]"
                
            # Thêm vào danh sách theo dõi
            self.suspicious_flows[flow_key] = flow_score
        
        # Thêm vào bảng
        self.table.add_row(
            str(self.packet_count),
            str(packet_data["src_ip"]),
            str(packet_data["dst_ip"]),
            str(packet_data["protocol"]),
            str(packet_data["src_port"]),
            str(packet_data["dst_port"]),
            str(packet_data["app_proto"]),
            str(packet_data["details"]),
            str(packet_data["size"]),
            Text(anomaly_text, style=anomaly_style),
            Text(str(flow_score), style=flow_style)
        )
    
    def update_display(self):
        """Cập nhật hiển thị bảng"""
        self.console.clear()
        
        # Tính thời gian đã chạy
        elapsed = time.time() - self.start_time
        
        # Tạo layout chính
        layout = Layout()
        layout.split_column(
            Layout(name="main", ratio=4),
            Layout(name="stats", ratio=1)
        )
        
        # Gán bảng chính
        layout["main"].update(self.table)
        
        # Tạo thống kê
        stats_table = Table.grid(padding=1)
        stats_table.add_column("Label", style="bold")
        stats_table.add_column("Value")
        
        stats_table.add_row("Thời gian chạy:", f"{int(elapsed//60):02d}:{int(elapsed%60):02d}")
        stats_table.add_row("Tổng số gói tin:", str(self.packet_count))
        stats_table.add_row("Số gói bất thường:", Text(str(self.anomaly_count), style="red" if self.anomaly_count > 0 else "green"))
        stats_table.add_row("Tỉ lệ bất thường:", f"{(self.anomaly_count/max(1, self.packet_count))*100:.2f}%")
        
        # Thêm luồng bất thường nếu có
        if self.suspicious_flows:
            suspicious_text = ""
            for flow, score in sorted(self.suspicious_flows.items(), key=lambda x: x[1], reverse=True)[:3]:
                suspicious_text += f"[red]{flow}[/red]: {score} lần bất thường\n"
            
            stats_panel = Panel(
                f"{stats_table}\n\n[bold red]Luồng đáng ngờ (Top 3):[/bold red]\n{suspicious_text}",
                title="[bold]Thống kê[/bold]",
                border_style="blue"
            )
        else:
            stats_panel = Panel(
                stats_table,
                title="[bold]Thống kê[/bold]",
                border_style="blue"
            )
        
        layout["stats"].update(stats_panel)
        
        # Hiển thị layout
        self.console.print(layout)
    
    def print_alert(self, message):
        """In thông báo cảnh báo"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alerts.append((timestamp, message))
        self.alerts = self.alerts[-10:]  # Chỉ giữ 10 cảnh báo gần nhất
        self.console.print(f"[bold red][{timestamp}] CẢNH BÁO: {message}[/bold red]")
    
    def show_summary(self):
        """Hiển thị bản tóm tắt cuối cùng"""
        elapsed = time.time() - self.start_time
        
        self.console.clear()
        
        summary_table = Table.grid(padding=1)
        summary_table.add_column("Label", style="bold")
        summary_table.add_column("Value")
        
        summary_table.add_row("Tổng thời gian:", f"{int(elapsed//60):02d} phút {int(elapsed%60):02d} giây")
        summary_table.add_row("Tổng số gói tin:", str(self.packet_count))
        summary_table.add_row("Số gói bất thường:", Text(str(self.anomaly_count), style="red" if self.anomaly_count > 0 else "green"))
        summary_table.add_row("Tỉ lệ bất thường:", f"{(self.anomaly_count/max(1, self.packet_count))*100:.2f}%")
        
        # Thêm thông tin luồng bất thường
        flow_text = ""
        if self.suspicious_flows:
            for flow, score in sorted(self.suspicious_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
                flow_text += f"[red]{flow}[/red]: {score} lần bất thường\n"
        else:
            flow_text = "[green]Không phát hiện luồng bất thường đáng kể[/green]"
        
        # Thêm cảnh báo gần đây
        alert_text = ""
        if self.alerts:
            for timestamp, message in self.alerts:
                alert_text += f"[{timestamp}] {message}\n"
        else:
            alert_text = "[green]Không có cảnh báo nào[/green]"
        
        summary = Panel(
            f"{summary_table}\n\n[bold]Luồng bất thường hàng đầu:[/bold]\n{flow_text}\n\n[bold]Cảnh báo gần đây:[/bold]\n{alert_text}",
            title="[bold]Báo cáo tổng kết[/bold]",
            border_style="cyan",
            width=100
        )
        
        self.console.print(summary)