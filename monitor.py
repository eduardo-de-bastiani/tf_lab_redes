import socket
import struct
import sys
import os
import csv
import datetime
from collections import defaultdict

# Dicionário de contadores para a UI
PACKET_COUNTERS = defaultdict(int)

# Armazena estatísticas detalhadas de comunicação entre clientes do túnel e máquinas remotas
CLIENT_STATS = defaultdict(lambda: defaultdict(lambda: {
    'bytes': 0,
    'pkts': 0,
    'ports': set(),
    'protos': set()
}))

# Funções auxiliares de formatação
def get_timestamp():
    """Retorna o timestamp atual formatado."""
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def format_mac(addr_bytes):
    """Formata um endereço MAC de bytes para string."""
    return ":".join(f"{b:02x}" for b in addr_bytes)

def guess_ip_version(packet_bytes):
    version = (packet_bytes[0] >> 4) & 0xF
    if version == 4:
        return 0x0800
    elif version == 6:
        return 0x86DD
    else:
        return None


def format_ipv4(addr_bytes):
    """Formata um endereço IPv4 de bytes para string."""
    return socket.inet_ntoa(addr_bytes)

def format_ipv6(addr_bytes):
    """Formata um endereço IPv6 de bytes para string."""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


def parse_dns(payload):
    """
    Extrai informação da query DNS ou resposta DNS.
    """
    try:
        # Cabeçalho DNS com 12 bytes fixo:
        header = struct.unpack('!HHHHHH', payload[:12])
        flags_word = header[1]
        qdcount = header[2]
        ancount = header[3]
        
        # Bit QR (0x8000): 1 = resposta, 0 = pergunta
        is_response = (flags_word & 0x8000) != 0
        
        if qdcount == 0:
            return "Pacote DNS (sem query)"

        # Parsear a seção de pergunta
        offset = 12
        (query_name, offset) = _dns_parse_name(payload, offset)
        
        # Após o nome vem QTYPE (2 bytes) e QCLASS (2 bytes)
        q_header = struct.unpack('!HH', payload[offset:offset+4])
        qtype = q_header[0]
        offset += 4 
        
        qtype_map = {
            1: 'A',
            28: 'AAAA',
            5: 'CNAME',
            15: 'MX',
            16: 'TXT',
            12: 'PTR',
            2: 'NS'
        }
        qtype_str = qtype_map.get(qtype, f'Tipo {qtype}')

        if not is_response:
            return f"Query ({qtype_str}): {query_name}"

        # Parsear seção de resposta se existir
        if ancount == 0:
            return f"Resposta para ({qtype_str}) {query_name} (sem respostas)"

        # Está no início do primeiro Answer Record
        (answer_name, offset) = _dns_parse_name(payload, offset)
        
        # Answer Record com 10 bytes
        ans_header = struct.unpack('!HHIH', payload[offset:offset+10])
        ans_type = ans_header[0]
        ans_rdlength = ans_header[3]
        offset += 10
        
        rdata = payload[offset : offset + ans_rdlength]

        # Decodificar os dados da resposta (RDATA) conforme o tipo
        if ans_type == 1:
            ip = socket.inet_ntoa(rdata)
            return f"Resposta (A): {answer_name} -> {ip}"
        
        elif ans_type == 28:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            return f"Resposta (AAAA): {answer_name} -> {ip}"
            
        elif ans_type == 5:
            (cname, _) = _dns_parse_name(payload, offset)
            return f"Resposta (CNAME): {answer_name} -> {cname}"
        
        else:
            ans_type_str = qtype_map.get(ans_type, f'Tipo {ans_type}')
            return f"Resposta ({ans_type_str}) para ({qtype_str}) {query_name}"

    except Exception as e:
        return f"Erro ao parsear DNS: {e}"


def _dns_parse_name(payload, offset):
    """
    Decodifica um nome DNS (ex: 'www.google.com').
    """
    name_parts = []
    original_offset = offset
    followed_pointer = False

    while True:
        length = payload[offset]
        
        if length == 0:
            offset += 1
            break
        
        if (length & 0xC0) == 0xC0:
            pointer_offset = struct.unpack('!H', payload[offset:offset+2])[0]
            pointer_offset &= 0x3FFF
            (pointed_name, _) = _dns_parse_name(payload, pointer_offset)
            name_parts.append(pointed_name)
            offset += 2
            followed_pointer = True
            break
        else:
            offset += 1
            name_parts.append(payload[offset : offset + length].decode('latin-1'))
            offset += length
    
    if followed_pointer:
        return (".".join(name_parts), original_offset + 2)
    else:
        return (".".join(name_parts), offset)


def parse_http(payload):
    """
    Extrai informação de requisição ou resposta HTTP.
    """
    try:
        http_data = payload.decode('latin-1')
        lines = http_data.split('\r\n')
        first_line = lines[0]

        # Busca headers adicionais (Host, User-Agent) para enriquecer o log
        # Verifica se é um método HTTP ou uma resposta
        is_http = False
        if first_line.startswith('HTTP/'):
            is_http = True
        else:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
            for method in methods:
                if first_line.startswith(method):
                    is_http = True
                    break
        
        if is_http:
            extracted_info = [first_line]
            # Itera sobre as linhas seguintes para encontrar headers relevantes
            for line in lines[1:]:
                if not line: break # Linha vazia indica fim dos headers
                lower_line = line.lower()
                if lower_line.startswith('host:') or lower_line.startswith('user-agent:'):
                    extracted_info.append(line.strip())
            return " | ".join(extracted_info)

        return "Fragmento HTTP"

    except Exception:
        return "Payload HTTP (binário/malformado)"


# Funções de UI e Log
def init_csv_files():
    """
    Cria os arquivos CSV e escreve os cabeçalhos se não existirem.
    """
    csv_files = {
        'net': ('camada_internet.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'IP Destino', 'Protocolo Superior', 'Tamanho']),
        'trans': ('camada_transporte.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'Porta Origem', 'IP Destino', 'Porta Destino', 'Tamanho']),
        'app': ('camada_aplicacao.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'IP Destino', 'Detalhes', 'Tamanho'])
    }
    
    writers = {}
    files = {}

    try:
        for key, (filename, headers) in csv_files.items():
            write_header = not os.path.exists(filename) or os.path.getsize(filename) == 0
            f = open(filename, 'a', newline='', encoding='utf-8')
            writer = csv.writer(f)
            if write_header:
                writer.writerow(headers)
            files[key] = f
            writers[key] = writer
            
        return files, writers
    except IOError as e:
        print(f"Erro ao abrir ou escrever nos arquivos CSV: {e}")
        print("Verifique as permissões de escrita no diretório.")
        sys.exit(1)


def update_text_ui():
    """Limpa a tela e exibe os contadores de pacotes."""
    os.system('clear')
    print("="*60)
    print(f"--- 🛰️ ATUALIZAÇÃO DO MONITOR @ {get_timestamp()} ---")
    print(f"Monitorando interface: {sys.argv[1]}\n")
    
    print("Contagem Global de Pacotes:")
    print("-" * 30)
    if not PACKET_COUNTERS:
        print("Aguardando pacotes...")
    
    sorted_counters = sorted(
        PACKET_COUNTERS.items(), 
        key=lambda item: item[1], 
        reverse=True
    )
    for proto, count in sorted_counters:
        print(f"| {proto:<15}: {count:>8}")
        
    # Exibição detalhada por cliente
    print("\n" + "="*60)
    print("DETALHES DOS CLIENTES (Rede Túnel 172.31.66.x)")
    print("="*60)
    
    if not CLIENT_STATS:
        print("Nenhum tráfego de cliente detectado ainda.")
    
    for client_ip, remotes in CLIENT_STATS.items():
        # Calcula total de tráfego do cliente somando todos os remotos
        total_bytes = sum(stats['bytes'] for stats in remotes.values())
        print(f"\n🟢 CLIENTE: {client_ip} | Total Tráfego: {total_bytes/1024:.2f} KB")
        print(f"   {'Máquina Remota':<20} | {'Proto':<10} | {'Pkts':<5} | {'Vol(B)':<8} | {'Portas'}")
        print("   " + "-"*55)
        
        for remote_ip, stats in remotes.items():
            # Formata listas de protocolos e portas para caber na linha
            protos_str = ",".join(list(stats['protos'])[:3])
            ports_str = ",".join(map(str, list(stats['ports'])[:5]))
            
            print(f"   -> {remote_ip:<17} | {protos_str:<10} | {stats['pkts']:<5} | {stats['bytes']:<8} | {ports_str}")

    print("\n" + "="*60)
    print("Pressione Ctrl+C para parar.")


def get_app_protocol(src_port, dst_port):
    """Identifica protocolos de aplicação baseados em portas conhecidas."""
    if src_port == 80 or dst_port == 80:
        return 'HTTP'
    if src_port == 53 or dst_port == 53:
        return 'DNS'
    if (src_port == 67 or dst_port == 67 or
        src_port == 68 or dst_port == 68):
        return 'DHCP'
    if src_port == 123 or dst_port == 123:
        return 'NTP'
    if src_port == 443 or dst_port == 443:
        return 'HTTPS'
    return 'Outro'


# Funções principais de parsing
def parse_application_layer(payload, ip_src, ip_dst, size, protocol_name, writers):
    """
    Loga protocolos da camada de aplicação.
    """
    PACKET_COUNTERS[protocol_name] += 1
    
    timestamp = get_timestamp()
    details = "" 

    if protocol_name == 'HTTP':
        details = parse_http(payload)
    elif protocol_name == 'DNS':
        details = parse_dns(payload)
    elif protocol_name == 'HTTPS':
        details = "Tráfego Criptografado (TLS)"
    
    if protocol_name != 'Outro':
        log_data = [timestamp, protocol_name, ip_src, ip_dst, details, size]
        writers['app'].writerow(log_data)


def parse_transport_layer(payload, ip_src, ip_dst, size, protocol_id, writers):
    """
    Decodifica TCP e UDP (Camada 4).
    """
    timestamp = get_timestamp()
    
    try:
        app_proto = 'Outro'
        l7_payload = b''
        src_port = 0
        dst_port = 0
        proto_name = ''

        # Protocolo 6 = TCP
        if protocol_id == 6:
            PACKET_COUNTERS['TCP'] += 1
            proto_name = 'TCP'
            header = struct.unpack('!HHLLHHHH', payload[:20])
            src_port = header[0]
            dst_port = header[1]
            
            offset_flags = header[4]
            tcp_header_len = ((offset_flags >> 12) & 0xF) * 4
            l7_payload = payload[tcp_header_len:]

        # Protocolo 17 = UDP
        elif protocol_id == 17:
            PACKET_COUNTERS['UDP'] += 1
            proto_name = 'UDP'
            header = struct.unpack('!HHHH', payload[:8])
            src_port = header[0]
            dst_port = header[1]
            
            l7_payload = payload[8:]
            
        if proto_name:
            log_data = [timestamp, proto_name, ip_src, src_port, ip_dst, dst_port, size]
            writers['trans'].writerow(log_data)

            app_proto = get_app_protocol(src_port, dst_port)

            # Atualiza as estatísticas na memória para a UI
            # Verifica se a origem é um cliente da rede túnel (Upload/Request)
            if ip_src.startswith("172.31.66."):
                client = ip_src
                remote = ip_dst
                stats = CLIENT_STATS[client][remote]
                stats['bytes'] += size
                stats['pkts'] += 1
                stats['ports'].add(dst_port)
                stats['protos'].add(app_proto)
            
            # Verifica se o destino é um cliente da rede túnel (Download/Response)
            elif ip_dst.startswith("172.31.66."):
                client = ip_dst
                remote = ip_src
                stats = CLIENT_STATS[client][remote]
                stats['bytes'] += size
                stats['pkts'] += 1
                stats['ports'].add(src_port)
                stats['protos'].add(app_proto)

            parse_application_layer(l7_payload, ip_src, ip_dst, size, app_proto, writers)
            
    except struct.error:
        PACKET_COUNTERS['Transport Error'] += 1

def parse_network_layer(packet_data, writers):
    """
    Decodifica camada de rede: IPv4, IPv6, ICMP.
    """
    timestamp = get_timestamp()

    # EtherType 0x0800 = IPv4
    if packet_data['ethertype'] == 0x0800:
        PACKET_COUNTERS['IPv4'] += 1
        
        try:
            header_data = packet_data['payload'][:20]
            header = struct.unpack('!BBHHHBBH4s4s', header_data)
            
            version_ihl = header[0]
            total_size = header[2]
            protocol_id = header[6]
            ip_src = format_ipv4(header[8])
            ip_dst = format_ipv4(header[9])
            
            ihl_bytes = (version_ihl & 0xF) * 4
            ip_payload = packet_data['payload'][ihl_bytes:]

            log_data = [timestamp, 'IPv4', ip_src, ip_dst, protocol_id, total_size]
            writers['net'].writerow(log_data)
            
            if protocol_id == 1:
                PACKET_COUNTERS['ICMP'] += 1
                log_data_icmp = [timestamp, 'ICMP', ip_src, ip_dst, '', total_size]
                writers['net'].writerow(log_data_icmp)

                # Adicionando suporte básico para ICMP nas stats de cliente para completude:
                if ip_src.startswith("172.31.66."):
                    CLIENT_STATS[ip_src][ip_dst]['bytes'] += total_size
                    CLIENT_STATS[ip_src][ip_dst]['pkts'] += 1
                    CLIENT_STATS[ip_src][ip_dst]['protos'].add("ICMP")
                elif ip_dst.startswith("172.31.66."):
                    CLIENT_STATS[ip_dst][ip_src]['bytes'] += total_size
                    CLIENT_STATS[ip_dst][ip_src]['pkts'] += 1
                    CLIENT_STATS[ip_dst][ip_src]['protos'].add("ICMP")

            else:
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)

        except struct.error:
            PACKET_COUNTERS['IPv4 Error'] += 1

    # EtherType 0x86DD = IPv6
    elif packet_data['ethertype'] == 0x86DD:
        PACKET_COUNTERS['IPv6'] += 1
        
        try:
            header_data = packet_data['payload'][:40]
            payload_size = struct.unpack('!H', header_data[4:6])[0]
            protocol_id = header_data[6]
            ip_src = format_ipv6(header_data[8:24])
            ip_dst = format_ipv6(header_data[24:40])
            
            total_size = 40 + payload_size
            
            log_data = [timestamp, 'IPv6', ip_src, ip_dst, protocol_id, total_size]
            writers['net'].writerow(log_data)
            
            ip_payload = packet_data['payload'][40:]
            
            if protocol_id == 58:
                PACKET_COUNTERS['ICMPV6'] += 1
                log_data_icmp = [timestamp, 'ICMPV6', ip_src, ip_dst, '', total_size]
                writers['net'].writerow(log_data_icmp)
            else:
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)
            
        except struct.error:
            PACKET_COUNTERS['IPv6 Error'] += 1

    # Outros EtherTypes (ARP 0x0806, etc)
    else:
        PACKET_COUNTERS['Outro (L2)'] += 1


def parse_link_layer(packet_bytes, writers):
    """
    Extrai frame Ethernet e passa para camada de rede.
    """
    try:
        header = struct.unpack('!6s6sH', packet_bytes[:14])
        
        packet_data = {
            'mac_dst': format_mac(header[0]),
            'mac_src': format_mac(header[1]),
            'ethertype': header[2],
            'payload': packet_bytes[14:]
        }
        
        parse_network_layer(packet_data, writers)
        
    except struct.error:
        PACKET_COUNTERS['Link Error'] += 1

def main():
    if os.geteuid() != 0:
        print("Erro: Este script deve ser executado como root (use sudo).")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Uso: sudo {sys.argv[0]} <interface>")
        sys.exit(1)
        
    interface_name = sys.argv[1]
    csv_files, csv_writers = init_csv_files()

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((interface_name, 0))
    except socket.error as e:
        print(f"Erro ao criar socket: {e}")
        sys.exit(1)

    print(f"--- Monitorando {interface_name} (CTRL+C para sair) ---")
    
    packet_count_since_ui_update = 0

    try:
        while True:
            raw_packet, addr = s.recvfrom(65535)

            if "tun" in interface_name:
                simulated_ethertype = guess_ip_version(raw_packet)
                
                if simulated_ethertype:
                    packet_data = {
                        'mac_dst': '00:00:00:00:00:00',
                        'mac_src': '00:00:00:00:00:00',
                        'ethertype': simulated_ethertype,
                        'payload': raw_packet
                    }
                    parse_network_layer(packet_data, csv_writers)
                else:
                    PACKET_COUNTERS['Desconhecido (TUN)'] += 1
            else:
                parse_link_layer(raw_packet, csv_writers)
            

            packet_count_since_ui_update += 1
            if packet_count_since_ui_update >= 1:
                update_text_ui()
                packet_count_since_ui_update = 0
                for f in csv_files.values():
                    f.flush()

    except KeyboardInterrupt:
        print("\n--- Monitor encerrado ---")
        update_text_ui()
    finally:
        s.close()
        for f in csv_files.values():
            f.close()

if __name__ == "__main__":
    main()
