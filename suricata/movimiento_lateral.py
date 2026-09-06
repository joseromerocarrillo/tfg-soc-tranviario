from scapy.all import *

# IPs reales del dataset — ajusta si los nodos reales de tu captura son distintos
SRC_IP = "192.168.21.24"   # nodo ofimática identificado en cap. 6
DST_IP = "192.168.2.101"   # servidor SCADA principal

pkts = []

# --- Paquetes SYN hacia cada puerto sensible ---
# Puerto 445 — SMB
pkts.append(
    IP(src=SRC_IP, dst=DST_IP) /
    TCP(sport=51001, dport=445, flags="S", seq=1000)
)

# Puerto 1433 — SQL Server
pkts.append(
    IP(src=SRC_IP, dst=DST_IP) /
    TCP(sport=51002, dport=1433, flags="S", seq=2000)
)

# Puerto 502 — Modbus
pkts.append(
    IP(src=SRC_IP, dst=DST_IP) /
    TCP(sport=51003, dport=502, flags="S", seq=3000)
)

# --- Conexión TCP completa simulada hacia 502 (para regla con established) ---
# SYN
pkts.append(
    IP(src=SRC_IP, dst=DST_IP) /
    TCP(sport=51004, dport=502, flags="S", seq=4000)
)
# SYN-ACK simulado desde el servidor (para que Suricata vea el handshake)
pkts.append(
    IP(src=DST_IP, dst=SRC_IP) /
    TCP(sport=502, dport=51004, flags="SA", seq=9000, ack=4001)
)
# ACK del cliente — conexión establecida
pkts.append(
    IP(src=SRC_IP, dst=DST_IP) /
    TCP(sport=51004, dport=502, flags="A", seq=4001, ack=9001)
)

wrpcap("/tmp/movimiento_lateral.pcap", pkts)
print(f"PCAP generado con {len(pkts)} paquetes.")