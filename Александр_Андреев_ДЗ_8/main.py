import argparse
import socket
import random
import time
from urllib.parse import urlparse, quote
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None

    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)

    time.sleep(0.1)

    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_request, verbose=False)

    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")

    print("BEFORE SNIFF", flush=True)

    packets = sniff(iface="eth0",
        filter=f"tcp port 80 and host {dest_ip}",
        timeout=timeout
    )

    print("AFTER SNIFF", len(packets), flush=True)  # TODO настройте перехват трафика

    # print(f"Перехвачено пакетов: {len(packets)}")

    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")
        print(f"Перехвачено пакетов: {len(packets)}")
        print(f"Трафик сохранен в {output_file}")
    return packets


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return

    http_data = []
    raw_chunks = []

    for pkt in packets:
        if pkt.haslayer('Raw'):
            try:
                data = pkt['Raw'].load.decode('utf-8', errors='ignore')
                raw_chunks.append(data)
                if 'HTTP' in data or 'GET' in data or 'POST' in data:
                    http_data.append(data)
            except:
                pass

    print(f"Найдено HTTP-сообщений: {len(http_data)}")

    # Выводим первые несколько HTTP-сообщений
    for i, data in enumerate(http_data[:3], 1):
        print(f"HTTP-сообщение {i} (первые 300 символов)")
        print(data[:300])

    # --- ЭТАПА 4 ---------------------------------

    xss_markers = ["<script", "alert(", "onerror=", "%3cscript", "%3cimg"]

    # Проверка XSS в HTTP-запросах
    print("\n[Этап 4] Поиск XSS в HTTP-зАПРОСАХ:")
    for data in http_data:
        if data.startswith("GET") or data.startswith("POST"):
            for marker in xss_markers:
                if marker.lower() in data.lower():
                    print("\n[!] Найдена XSS-полезная нагрузка в HTTP-запросе:")
                    print(data[:300])
                    break

    # Проверка отражённого XSS в HTTP-ответах
    print("\n[Этап 4] Поиск отражённого XSS в HTTP-ОТВЕТАХ:")
    for data in http_data:
        if data.startswith("HTTP/"):
            for marker in xss_markers:
                if marker.lower() in data.lower():
                    print("\n[!] Найдена отражённая XSS в HTTP-ответе:")
                    print(data[:300])
                    break

    # TODO для этапа 4: добавить анализ на наличие XSS-полезных нагрузок
    # TODO для этапа 4: добавить поиск отраженных XSS в ответах сервера


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)

def send_xss_payloads(instance_id, repeat=20, delay=0.2):
    """
    Выполняет попытки эксплуатации XSS с ограниченной нагрузкой.
    repeat — количество запросов
    delay — пауза между запросами (сек)
    """
    host = "google-gruyere.appspot.com"
    port = 80

    payloads = [
    "<script>document.body.style.background='red'</script>",
]

    print(f"[+] Старт XSS-нагрузки: {repeat} запросов, delay={delay}s")

    for i in range(repeat):
        payload = payloads[i % len(payloads)]
        encoded = quote(payload, safe="")
        path = f"/{instance_id}/snippets.gtl?search={encoded}"

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        )

        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(request.encode("utf-8"))
                _ = s.recv(512)
            print(f"[+] [{i+1}/{repeat}] payload отправлен")
        except Exception as e:
            print(f"[-] Ошибка на запросе {i+1}: {e}")

        time.sleep(delay)

    print("[+] Нагрузка завершена")


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Примеры использования:
            # Отправка HTTP-запроса
            python scapy_xss_analyzer.py --send google-gruyere.appspot.com/XXXXX

            # Перехват трафика
            python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap

            # Анализ сохраненного трафика
            python scapy_xss_analyzer.py --analyze traffic.pcap
        """
    )

    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )

    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )

    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )

    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )

    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос (для этапа 3)'
    )

    parser.add_argument(
        '--xss-load',
        metavar='INSTANCE_ID',
        help='Отправить серию XSS payload (нагрузка) на указанный instance id'
    )

    args = parser.parse_args()

    # Проверка аргументов
    if not any([args.send, args.capture, args.analyze, args.xss_load]):
        parser.print_help()
        return

    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return

        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        if result:
            print("HTTP-запрос отправлен")
        else:
            print("Ошибка при отправке HTTP-запроса")

    # Перехват трафика
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)

    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze)

    # Имитация атаки
    if args.xss_load:
        send_xss_payloads(
            instance_id=args.xss_load,
            repeat=5,
            delay=0.2
        )





if __name__ == '__main__':
    main()

