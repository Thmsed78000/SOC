import re, json, time
from datetime import datetime, timedelta
from collections import defaultdict

log_file_path = '/var/log/owncloud.log'
alert_file_path = '/opt/ids/alertessiem.csv'
server_ip = '192.168.1.240'

bruteforce_threshold = 3
bruteforce_time_window = timedelta(seconds=5)

ip_attempts = defaultdict(list)
processed_messages = set()
sqli_detected = set()
auth_fail_detected = set()

def parse_log_line(line):
    json_match = re.search(r'(\{.*\})', line)
    if json_match:
        try: return json.loads(json_match.group(1))
        except json.JSONDecodeError: pass
    login_match = re.search(r'Login failed:.*Remote IP: \'([\d\.]+)\'', line)
    if login_match:
        return {
            'message': line,
            'remoteAddr': login_match.group(1),
            'time': datetime.now().isoformat()
        }
    return None

def log_alert(alert_type, attacker_ip, timestamp, severity):
    with open(alert_file_path, 'a') as alert_file:
        alert_file.write(f"{alert_type},{attacker_ip},{server_ip},,{timestamp},{severity}\n")

def detect_bruteforce(entry):
    if entry and ('Login failed' in entry.get('message', '')):
        ip = entry.get('remoteAddr')
        if not ip:
            ip_match = re.search(r"Remote IP: '([\d\.]+)'", entry.get('message', ''))
            if ip_match: ip = ip_match.group(1)
            else: return
        message_hash = hash(f"{ip}-{entry.get('time', datetime.now().isoformat())}")
        if message_hash in processed_messages: return
        processed_messages.add(message_hash)
        if len(processed_messages) > 1000: processed_messages.clear()
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[{timestamp}] [BASSE] Tentative de connexion échouée depuis l'IP: {ip}")
        if message_hash not in auth_fail_detected:
            log_alert("AUTH_FAIL", ip, timestamp, "BASSE")
            auth_fail_detected.add(message_hash)
        ip_attempts[ip].append(current_time)
        ip_attempts[ip] = [t for t in ip_attempts[ip] if current_time - t <= bruteforce_time_window]
        recent_attempts = len(ip_attempts[ip])
        if recent_attempts >= bruteforce_threshold:
            print(f"[{timestamp}] [HAUTE] Bruteforce détecté de l'IP: {ip} - {recent_attempts} tentatives en {bruteforce_time_window.seconds} secondes")
            log_alert("BRUTEFORCE", ip, timestamp, "HAUTE")
            ip_attempts[ip] = [current_time]

def detect_sql_injection(entry):
    if not entry or 'message' not in entry: return
    message = entry['message']
    patterns = [
        r'\b(UNION\s+ALL\s+SELECT|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE)\b',
        r'\b(--|\/\*|\*\/|;)\b'
    ]
    if any(re.search(pattern, message, re.IGNORECASE) for pattern in patterns):
        ip = entry.get('remoteAddr', 'inconnu')
        if ip == 'inconnu':
            ip_match = re.search(r"Remote IP: '([\d\.]+)'", message)
            if ip_match: ip = ip_match.group(1)
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        message_hash = hash(f"{ip}-{entry.get('time', datetime.now().isoformat())}")
        if message_hash in sqli_detected: return
        print(f"[{timestamp}] [HAUTE] Injection SQL détectée de l'IP: {ip}")
        log_alert("SQLI", ip, timestamp, "HAUTE")
        sqli_detected.add(message_hash)

def main():
    print("Démarrage du script de surveillance...")
    print(f"Surveillance du fichier: {log_file_path}")
    print(f"Seuil de bruteforce: {bruteforce_threshold} tentatives en {bruteforce_time_window.seconds} secondes")
    print("Le script affichera une nouvelle alerte après chaque série de tentatives de bruteforce")
    try:
        with open(log_file_path, 'r') as file:
            file.seek(0, 2)
            print("Surveillance active. En attente de nouvelles entrées de log...")
            while True:
                line = file.readline()
                if line:
                    entry = parse_log_line(line)
                    if entry:
                        detect_sql_injection(entry)
                        detect_bruteforce(entry)
                else:
                    time.sleep(0.5)
    except FileNotFoundError:
        print(f"ERREUR: Le fichier {log_file_path} n'existe pas.")
    except PermissionError:
        print(f"ERREUR: Pas de permission pour lire {log_file_path}.")
    except KeyboardInterrupt:
        print("\nSurveillance arrêtée par l'utilisateur.")
    except Exception as e:
        print(f"ERREUR inattendue: {e}")

if __name__ == "__main__":
    main()
