import os
import queue
import socket
import struct
import sys
import threading

import pyfiglet
import requests

API_URL = "http://127.0.0.1:3000/api/packets"
IGNORAR = {3000, 5432}  # tráfego da própria API e do banco (evita loop de captura)
PROTOCOLOS = {1: "ICMP", 6: "TCP", 17: "UDP"}
FLAGS_TCP = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U")]

fila = queue.Queue(maxsize=10000)


def enviador():
    """Thread que envia os pacotes para a API sem travar o sniffer."""
    sessao = requests.Session()  # reaproveita a conexão HTTP
    while True:
        dado = fila.get()
        try:
            sessao.post(API_URL, json=dado, timeout=2)
        except requests.RequestException:
            pass  # API fora do ar: descarta o pacote


threading.Thread(target=enviador, daemon=True).start()


def ip_local():
    """Descobre o IP local da máquina (usado no Windows)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # não envia nada, só descobre a rota
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def decodificar(pacote):
    """Lê o cabeçalho IPv4 e, quando houver, TCP/UDP/ICMP. Devolve um dict ou None."""
    if len(pacote) < 20 or pacote[0] >> 4 != 4:
        return None
    ihl = (pacote[0] & 0x0F) * 4
    if ihl < 20 or len(pacote) < ihl:
        return None

    comprimento = struct.unpack("!H", pacote[2:4])[0]
    fragmento = struct.unpack("!H", pacote[6:8])[0] & 0x1FFF  # offset do fragmento
    ttl, proto = pacote[8], pacote[9]

    dado = {
        "protocol": PROTOCOLOS.get(proto, str(proto)),
        "src": socket.inet_ntoa(pacote[12:16]),
        "dst": socket.inet_ntoa(pacote[16:20]),
        "length": comprimento,
        "ttl": ttl,
    }

    # fragmentos depois do primeiro não têm cabeçalho de transporte
    camada4 = pacote[ihl:] if fragmento == 0 else b""
    if proto in (6, 17) and len(camada4) >= 4:
        dado["src_port"], dado["dst_port"] = struct.unpack("!HH", camada4[:4])
        if proto == 6 and len(camada4) >= 14:
            dado["flags"] = camada4[13]
    elif proto == 1 and len(camada4) >= 2:
        dado["icmp_type"], dado["icmp_code"] = camada4[0], camada4[1]
    return dado


def texto_flags(valor):
    return "".join(letra for bit, letra in FLAGS_TCP if valor & bit) or "-"


# ---------- interface do usuário ----------
print(pyfiglet.figlet_format("sniffar"))
print("analyse on ip and sniffer and decode")

# o IP pode vir como argumento: sudo python sniffer_analyse.py 192.168.1.106
if len(sys.argv) > 1:
    filtro = sys.argv[1].strip()
else:
    filtro = input("digite o IP para filtrar (enter = mostrar tudo): ").strip()
if filtro:
    try:
        socket.inet_aton(filtro)
    except OSError:
        print("IP inválido.")
        raise SystemExit(1)

# ---------- criação do socket ----------
if os.name == "nt":
    host = ip_local()
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    eth_offset = 0
else:
    # captura todos os pacotes de todas as interfaces (precisa de sudo)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    eth_offset = 14  # tamanho do cabeçalho Ethernet

print("Capturando... (Ctrl+C para parar)\n")

try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]

        # no Linux, ignora quem não é IPv4 (ethertype 0x0800)
        if eth_offset and raw_buffer[12:14] != b"\x08\x00":
            continue

        dado = decodificar(raw_buffer[eth_offset:])
        if dado is None:
            continue

        if IGNORAR & {dado.get("src_port"), dado.get("dst_port")}:
            continue

        if filtro and filtro not in (dado["src"], dado["dst"]):
            continue

        origem = f'{dado["src"]}:{dado["src_port"]}' if "src_port" in dado else dado["src"]
        destino = f'{dado["dst"]}:{dado["dst_port"]}' if "dst_port" in dado else dado["dst"]
        extra = f' [{texto_flags(dado["flags"])}]' if "flags" in dado else ""
        print(f'{dado["protocol"]:<5} {origem} -> {destino}{extra} len={dado["length"]}')

        try:
            fila.put_nowait(dado)
        except queue.Full:
            pass

except KeyboardInterrupt:
    print("\nParado.")

finally:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
