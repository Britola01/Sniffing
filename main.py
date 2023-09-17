import socket

import nmap
import requests
import scapy

host = input("Digite o domínio: ")
ip = socket.gethostbyname(host)

def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, ports)
    
    open_ports = []
    
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
    
    return open_ports

target_ip = ip
target_ports = "1-100"

open_ports = scan_ports(target_ip, target_ports)

if open_ports:
    print(f"Portas abertas em {target_ip}: {open_ports}")
else:
    print("Nenhuma porta aberta encontrada")
scapyall = ip
# capturar tráfego de rede
sniffer = scapyall.sniff(filter="tcp", prn=lambda x: print(x.summary()))

# enviar solicitação HTTP
response = requests.get(host)

# analisar resposta HTTP
print(response.status_code)
print(response.content)