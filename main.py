import os
import sys
import pcap
from colorama import init, Fore
from analyzer.packet_sniffer import PacketSniffer
from analyzer.pcap_analyzer import analyze_pcap_file
from config import DEFAULT_INTERFACE, DEFAULT_OUTPUT_DIR, DEFAULT_MODEL_PATH

init(autoreset=True)

def main():
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "     PACKET SNIFFER VỚI PHÁT HIỆN BẤT THƯỜNG NÂNG CAO")
    print(Fore.CYAN + "=" * 60)
    
    # Kiểm tra quyền root
    if os.geteuid() != 0:
        print(Fore.RED + "[!] Script này phải được chạy với quyền sudo để bắt gói tin.")
        sys.exit(1)
    
    # Hỏi người dùng có muốn phân tích file PCAP sẵn có không
    analyze_choice = input(Fore.YELLOW + "Bạn muốn phân tích file PCAP có sẵn? (y/n): ").lower()
    
    if analyze_choice == 'y':
        # Phân tích file PCAP có sẵn
        pcap_file = input(Fore.YELLOW + "Nhập đường dẫn đến file PCAP: ")
        if not os.path.exists(pcap_file):
            print(Fore.RED + f"[!] File PCAP không tồn tại: {pcap_file}")
            sys.exit(1)
            
        model_path = input(Fore.YELLOW + f"Nhập đường dẫn đến file mô hình (Enter để sử dụng mặc định {DEFAULT_MODEL_PATH}): ")
        if not model_path:
            model_path = DEFAULT_MODEL_PATH
            
        print(Fore.CYAN + f"[+] Bắt đầu phân tích file: {pcap_file}")
        analyze_pcap_file(pcap_file, model_path=model_path)
        sys.exit(0)
    
    # Bắt gói tin mới
    try:
        # Liệt kê các thiết bị mạng
        devices = pcap.findalldevs()
        if not devices:
            print(Fore.RED + "[!] Không tìm thấy thiết bị mạng nào.")
            sys.exit(1)
            
        print(Fore.CYAN + "\nCác interface mạng hiện có:")
        for i, device in enumerate(devices):
            print(Fore.GREEN + f"{i}: {device}")
            
        # Chọn interface
        while True:
            try:
                choice = input(Fore.YELLOW + "\nChọn số interface để bắt gói tin: ")
                device_index = int(choice)
                if 0 <= device_index < len(devices):
                    interface = devices[device_index]
                    break
                else:
                    print(Fore.RED + f"[!] Số không hợp lệ. Vui lòng chọn từ 0 đến {len(devices)-1}.")
            except ValueError:
                print(Fore.RED + "[!] Vui lòng nhập một số.")
        
        # Nhập filter
        filter_exp = input(Fore.YELLOW + "\nNhập filter BPF (để trống nếu không cần): ")
        
        # Nhập số lượng gói tin tối đa
        count_input = input(Fore.YELLOW + "\nNhập số lượng gói tin tối đa muốn bắt (Enter để bắt không giới hạn): ")
        count = int(count_input) if count_input.strip() else None
        
        # Nhập thư mục lưu trữ
        output_dir = input(Fore.YELLOW + f"\nNhập thư mục lưu file PCAP (Enter để sử dụng mặc định {DEFAULT_OUTPUT_DIR}): ")
        if not output_dir:
            output_dir = DEFAULT_OUTPUT_DIR
            
        # Nhập file mô hình
        model_path = input(Fore.YELLOW + f"\nNhập đường dẫn đến file mô hình (Enter để sử dụng mặc định {DEFAULT_MODEL_PATH}): ")
        if not model_path:
            model_path = DEFAULT_MODEL_PATH
        
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + f"[+] Sử dụng interface: {interface}")
        if filter_exp:
            print(Fore.CYAN + f"[+] Áp dụng filter: {filter_exp}")
        if count:
            print(Fore.CYAN + f"[+] Số lượng gói tin tối đa: {count}")
        print(Fore.CYAN + f"[+] Thư mục lưu PCAP: {output_dir}")
        print(Fore.CYAN + f"[+] File mô hình: {model_path}")
        print(Fore.CYAN + "=" * 60)
        
        # Xác nhận trước khi bắt đầu
        confirm = input(Fore.YELLOW + "\nBắt đầu bắt gói tin? (y/n): ").lower()
        if confirm != 'y':
            print(Fore.RED + "[!] Đã hủy bắt gói tin.")
            sys.exit(0)
        
        # Khởi tạo PacketSniffer và bắt đầu bắt gói tin
        sniffer = PacketSniffer(
            interface=interface,
            output_dir=output_dir,
            model_path=model_path,
            filter_exp=filter_exp
        )
        
        print(Fore.GREEN + "\n[+] Bắt đầu bắt gói tin... Nhấn Ctrl+C để dừng")
        sniffer.start_sniffing(max_packets=count)
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Đã dừng bắt gói tin theo yêu cầu người dùng.")
    except Exception as e:
        print(Fore.RED + f"\n[!] Lỗi không xử lý được: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()