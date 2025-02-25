import requests
import sys
import os
from colorama import init, Fore, Style
from pathlib import Path
import json

# colorama 초기화
init()

def get_config_dir():
    """설정 디렉토리 경로 반환"""
    return Path.home() / '.cip'

def get_api_key_file():
    """API 키 파일 경로 반환"""
    return get_config_dir() / 'api_key.txt'

def validate_api_key(api_key):
    """API 키 유효성 검증 및 사용자 정보 반환"""
    url = "https://api.criminalip.io/v1/user/me"
    headers = {"x-api-key": api_key}
    
    try:
        response = requests.post(url, headers=headers)  # POST 메서드로 API 호출
        if response.status_code == 200:
            return response.json()  # 유효한 API 키일 경우 JSON 반환
        return None  # 유효하지 않은 API 키일 경우 None 반환
    except Exception as e:
        print("An error occurred:", e)
        return None


def initialize_api_key(api_key):
    """API 키 초기화 및 저장"""
    config_dir = get_config_dir()
    api_key_file = get_api_key_file()

    # 설정 디렉토리 생성
    if not config_dir.exists():
        config_dir.mkdir()
        print(f"{Fore.GREEN}[+] Work directory created at {config_dir}{Style.RESET_ALL}")

    # API 키 유효성 검증
    user_info = validate_api_key(api_key)
    if user_info:
        print(f"{Fore.GREEN}[+] API key is valid")
        print(f"[+] API key check successful.{Style.RESET_ALL}")
        
        # 사용자 정보 출력
        data = user_info.get('data', {})
        print(f"EMAIL:{data.get('email', 'N/A')}")
        print(f"NAME:{data.get('name', 'N/A')}")
        print(f"LAST_ACCESS_DATE:{data.get('last_access_date', 'N/A')}")
        print(f"MAX_SEARCH:{data.get('max_search', 'N/A')}")
        
        # API 키 저장
        with open(api_key_file, 'w') as f:
            f.write(api_key)
        print(f"{Fore.GREEN}[+] API key stored in {api_key_file}{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[-] Invalid API key{Style.RESET_ALL}")
        return False

def load_api_key():
    """저장된 API 키 로드"""
    api_key_file = get_api_key_file()
    if api_key_file.exists():
        return api_key_file.read_text().strip()
    return None

def print_header(text):
    """섹션 헤더 출력"""
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Style.BRIGHT}{text}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def print_field(label, value, color=Fore.WHITE):
    """필드 출력"""
    print(f"{Fore.YELLOW}{label}: {color}{value}{Style.RESET_ALL}")

# 악성 정보 및 개방 포트, 취약성 정보 가져오기
def get_malicious_data(ip, api_key):
    url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={ip}"
    headers = {"x-api-key": api_key}
    response = requests.get(url, headers=headers)
    return response.json()

# 기본 정보 가져오기
def get_summary_data(ip, api_key):
    url = f"https://api.criminalip.io/v1/asset/ip/summary?ip={ip}"
    headers = {"x-api-key": api_key}
    response = requests.get(url, headers=headers)
    return response.json()

def process_options(options):
    """옵션 문자열을 개별 옵션으로 분리"""
    valid_options = {'c', 'm', 'p', 'a'}
    if not options.startswith('-'):
        return []
    
    options = options[1:]
    selected_options = []
    
    if 'a' in options:
        return ['-c', '-m', '-p']
    
    for char in options:
        if char in valid_options:
            option = f"-{char}"
            if option not in selected_options:
                selected_options.append(option)
    
    return selected_options

def print_basic_info(data):
    """기본 정보 출력"""
    print_header("기본 정보")
    
    country = data.get("country", "N/A")
    isp = data.get("isp", "N/A")
    score = data.get("score", {}).get("inbound", "N/A")
    
    # 점수에 따른 색상 설정
    score_color = Fore.GREEN if score == "Safe" else Fore.RED
    
    print_field("국가", country)
    print_field("ISP", isp)
    print_field("Inbound IP Score", score, score_color)

def print_vulnerability_info(data):
    """취약성 정보 출력"""
    print_header("취약성 정보")
    
    vulnerabilities = data.get("vulnerability", {}).get("data", [])
    if vulnerabilities:
        print(f"{Fore.WHITE}발견된 취약성: {Fore.RED}{len(vulnerabilities)}개{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            port = vuln.get("ports", {}).get("tcp", "N/A")
            cve_id = vuln.get("cve_id", "N/A")
            cvssv3_score = vuln.get("cvssv3_score", "N/A")
            
            # CVSS 점수에 따른 색상 설정
            score_color = Fore.GREEN
            if cvssv3_score != "N/A":
                score = float(cvssv3_score)
                if score >= 7.0:
                    score_color = Fore.RED
                elif score >= 4.0:
                    score_color = Fore.YELLOW
            
            print(f"\n{Fore.CYAN}CVE ID: {Fore.WHITE}{cve_id}")
            print_field("  포트", port)
            print_field("  CVSSv3 점수", f"{cvssv3_score}", score_color)
    else:
        print(f"{Fore.GREEN}취약성이 없습니다.{Style.RESET_ALL}")

def print_malicious_info(data):
    """악성 정보 출력"""
    print_header("악성 정보")
    
    is_vpn = data.get("is_vpn", "N/A")
    is_malicious = data.get("is_malicious", "N/A")
    
    vpn_color = Fore.YELLOW if is_vpn else Fore.GREEN
    malicious_color = Fore.RED if is_malicious else Fore.GREEN
    
    print_field("VPN 사용 여부", str(is_vpn), vpn_color)
    print_field("최근 악성 활동 여부", str(is_malicious), malicious_color)

def print_port_info(data):
    """포트 정보 출력"""
    print_header("개방 포트 정보")
    
    open_ports = data.get("current_opened_port", {}).get("data", [])
    if open_ports:
        print(f"{Fore.WHITE}발견된 포트: {Fore.YELLOW}{len(open_ports)}개{Style.RESET_ALL}\n")
        # 포트를 프로토콜별로 분류
        common_ports = []
        unknown_ports = []
        
        for port_info in open_ports:
            port = port_info.get("port", "N/A")
            protocol = port_info.get("protocol", "None")
            
            if protocol and protocol != "None":
                common_ports.append((port, protocol))
            else:
                unknown_ports.append(port)
        
        if common_ports:
            print(f"{Fore.CYAN}일반 포트:{Style.RESET_ALL}")
            for port, protocol in common_ports:
                print(f"{Fore.WHITE}  ∟ {Fore.GREEN}포트: {port}{Fore.WHITE}, 프로토콜: {protocol}{Style.RESET_ALL}")
        
        if unknown_ports:
            print(f"\n{Fore.CYAN}알 수 없는 포트:{Style.RESET_ALL}")
            for port in unknown_ports:
                print(f"{Fore.WHITE}  ∟ {Fore.YELLOW}포트: {port}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}개방된 포트가 없습니다.{Style.RESET_ALL}")

# 도메인 기본 정보 가져오기
def get_domain_summary(domain, api_key):
    """도메인 기본 정보 조회"""
    url = f"https://api.criminalip.io/v1/domain/summary?query={domain}"
    headers = {"x-api-key": api_key}
    response = requests.get(url, headers=headers)
    response_data = response.json()
    
    # 전체 응답 JSON 출력
    print("Full Domain Summary JSON Response:", json.dumps(response_data, indent=4))
    return response.json()

def print_domain_info(data):
    """도메인 정보 출력"""
    print_header("도메인 정보")
    
    domain_data = data.get("data", {})
    
    # 기본 정보 출력
    registrar = domain_data.get("registrar", "N/A")
    creation_date = domain_data.get("creation_date", "N/A")
    expiration_date = domain_data.get("expiration_date", "N/A")
    is_blacklisted = domain_data.get("is_blacklisted", False)
    
    # 블랙리스트 상태에 따른 색상 설정
    blacklist_color = Fore.RED if is_blacklisted else Fore.GREEN
    
    print_field("등록 기관", registrar)
    print_field("생성일", creation_date)
    print_field("만료일", expiration_date)
    print_field("블랙리스트 여부", str(is_blacklisted), blacklist_color)
    
    # DNS 레코드 정보 출력
    print_header("DNS 레코드")
    dns_records = domain_data.get("dns_records", {})
    
    if dns_records:
        # A 레코드
        a_records = dns_records.get("a", [])
        if a_records:
            print(f"\n{Fore.CYAN}A 레코드:{Style.RESET_ALL}")
            for record in a_records:
                print(f"  ∟ {Fore.WHITE}{record}{Style.RESET_ALL}")
        
        # MX 레코드
        mx_records = dns_records.get("mx", [])
        if mx_records:
            print(f"\n{Fore.CYAN}MX 레코드:{Style.RESET_ALL}")
            for record in mx_records:
                print(f"  ∟ {Fore.WHITE}{record}{Style.RESET_ALL}")
        
        # NS 레코드
        ns_records = dns_records.get("ns", [])
        if ns_records:
            print(f"\n{Fore.CYAN}NS 레코드:{Style.RESET_ALL}")
            for record in ns_records:
                print(f"  ∟ {Fore.WHITE}{record}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}DNS 레코드를 찾을 수 없습니다.{Style.RESET_ALL}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] == '-h':
        print(f"{Fore.CYAN}사용법:{Style.RESET_ALL}")
        print(f"  python script_name.py <command> [options]")
        print("\n명령어:")
        print(f"  {Fore.YELLOW}init <api_key>{Style.RESET_ALL}    - API 키를 초기화하고 저장합니다.")
        print(f"  {Fore.YELLOW}ip <ip_address> [options]{Style.RESET_ALL} - 지정된 IP 주소에 대한 정보를 분석합니다.")
        print(f"  {Fore.YELLOW}domain <domain_name>{Style.RESET_ALL} - 지정된 도메인에 대한 정보를 분석합니다.")
        print("\nIP 분석 옵션:")
        print(f"  {Fore.YELLOW}-c{Style.RESET_ALL}      - 취약성 정보 출력")
        print(f"  {Fore.YELLOW}-m{Style.RESET_ALL}      - 악성 정보 출력")
        print(f"  {Fore.YELLOW}-p{Style.RESET_ALL}      - 개방 포트 정보 출력")
        print(f"  {Fore.YELLOW}-a{Style.RESET_ALL}      - 기본 정보, 취약성, 악성, 개방 포트 정보를 모두 출력")
        print(f"\n예시:")
        print(f"  python script_name.py init <api_key>")
        print(f"  python script_name.py ip 1.1.1.1 -a")
        print(f"  python script_name.py domain example.com\n")
        return

    command = sys.argv[1]

    if command == 'init':
        if len(sys.argv) < 3:
            print(f"{Fore.RED}Usage: python script_name.py init <api_key>{Style.RESET_ALL}")
            return
        api_key = sys.argv[2]
        initialize_api_key(api_key)
        return

    elif command == 'ip':
        if len(sys.argv) < 3:
            print(f"{Fore.RED}Usage: python script_name.py ip <ip_address> [-c | -m | -p | -a | -cmp | -mpc | ...]{Style.RESET_ALL}")
            return

        # API 키 로드
        api_key = load_api_key()
        if not api_key:
            print(f"{Fore.RED}[-] API key not found. Please run 'python script_name.py init <api_key>' first{Style.RESET_ALL}")
            return

        ip_address = sys.argv[2]
        options = sys.argv[3] if len(sys.argv) > 3 else ""
        
        print(f"\n{Fore.CYAN}[*] IP 주소 {Fore.WHITE}{ip_address}{Fore.CYAN} 분석 중...{Style.RESET_ALL}")
        
        active_options = process_options(options)
        
        if 'a' in options or not active_options:
            basic_data = get_summary_data(ip_address, api_key)
            print_basic_info(basic_data)

        if active_options or 'a' in options:
            data = get_malicious_data(ip_address, api_key)
            
            for option in active_options:
                if option == '-c':
                    print_vulnerability_info(data)
                elif option == '-m':
                    print_malicious_info(data)
                elif option == '-p':
                    print_port_info(data)
        
        print(f"\n{Fore.CYAN}[*] 분석 완료{Style.RESET_ALL}\n")
    
    elif command == 'domain':
        if len(sys.argv) < 3:
            print(f"{Fore.RED}Usage: python script_name.py domain <domain_name>{Style.RESET_ALL}")
            return

        # API 키 로드
        api_key = load_api_key()
        if not api_key:
            print(f"{Fore.RED}[-] API key not found. Please run 'python script_name.py init <api_key>' first{Style.RESET_ALL}")
            return

        domain_name = sys.argv[2]
        print(f"\n{Fore.CYAN}[*] 도메인 {Fore.WHITE}{domain_name}{Fore.CYAN} 분석 중...{Style.RESET_ALL}")
        
        # 도메인 정보 조회 및 출력
        domain_data = get_domain_summary(domain_name, api_key)
        print_domain_info(domain_data)
        
        print(f"\n{Fore.CYAN}[*] 분석 완료{Style.RESET_ALL}\n")
    
    else:
        print(f"{Fore.RED}Unknown command: {command}{Style.RESET_ALL}")
        print("Available commands:")
        print("  init <api_key>    Initialize API key")
        print("  ip <ip_address> [-c | -m | -p | -a | -cmp | -mpc | ...]    Analyze IP address")
        print("  domain <domain_name>    Analyze domain")

if __name__ == "__main__":
    main()