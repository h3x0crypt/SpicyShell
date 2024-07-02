import socket
import re
from ipaddress import ip_network
from colorama import Fore, init

init(autoreset=True)


def is_valid_ip_range(ip_range):
    try:
        ip_network(ip_range)
        return True
    except ValueError:
        return False


def is_ssh_port_open(ip, port=22, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
    except socket.error:
        return False
    finally:
        sock.close()
    return True


def scan_ssh_ports(ip_range):
    open_ports = []
    for ip in ip_network(ip_range):
        print(f"Scanning {ip}...")
        if is_ssh_port_open(str(ip)):
            print(f"{Fore.GREEN}>> Live IP with open SSH port found: {Fore.RESET}{ip}")
            open_ports.append(str(ip))
    return open_ports


def get_ssh_version(ip, port=22, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except socket.error as e:
        return f"Error connecting to {ip}:{port} - {e}"


def is_version_in_range(version, min_version="8.5", max_version="9.8"):
    version_pattern = re.compile(r"OpenSSH[\s_-]*(\d+\.\d+)")
    match = version_pattern.search(version)
    if match:
        version_number = match.group(1)
        return min_version <= version_number <= max_version
    return False


if __name__ == "__main__":
    ip_range = input("Enter IP RANGE (192.168.0.1/24) :")
    open_ssh_ports = scan_ssh_ports(ip_range)

    if not is_valid_ip_range(ip_range):
        print(f"{Fore.RED}Invalid IP range. Please enter a valid IP range.{Fore.RESET}")
        exit()

    if open_ssh_ports:
        print("Open SSH ports found on the following IP addresses:")
        for ip in open_ssh_ports:
            print(ip)
            ssh_version = get_ssh_version(ip)
            if "SSH" in ssh_version:
                print(f"SSH version on {ip}: {ssh_version}")
                if is_version_in_range(ssh_version):
                    print(
                        f"{ip} >> {Fore.GREEN} VULNERABLE {Fore.RESET} >> SSH version : {Fore.GREEN}{ssh_version}")
                    open("vulnerable.txt", "a").write(f"{ip}\n")
                else:
                    print(f"{ip} >> {Fore.RED} NOT VULNERABLE >> SSH version : {ssh_version}")
            else:
                print(ssh_version)
    else:
        print("No open SSH ports found.")
