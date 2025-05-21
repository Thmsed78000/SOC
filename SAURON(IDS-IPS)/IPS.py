import time, subprocess, csv
from datetime import datetime
from termcolor import colored

def is_ip_blocked(remote_host, attacker_ip, ssh_user):
    cmd = f"ssh {ssh_user}@{remote_host} 'ufw status numbered'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return any(attacker_ip in line for line in result.stdout.split('\n'))

def block_ip(victim_host, attacker_ip, ssh_user):
    if not is_ip_blocked(victim_host, attacker_ip, ssh_user):
        cmd = f"ssh {ssh_user}@{victim_host} 'ufw deny from {attacker_ip}'"
        subprocess.run(cmd, shell=True, check=True)
        if is_ip_blocked(victim_host, attacker_ip, ssh_user):
            print(colored(f"IP {attacker_ip} BLOCKED WITH UFW ON {victim_host}", "green"))
            log_blocking(ssh_user, victim_host, attacker_ip)
        else:
            print("[!] Failed to block IP")
    else:
        print(f"[-] IP {attacker_ip} is already blocked on {victim_host}")

def log_blocking(blocking_host, victim_host, blocked_ip):
    log_file = "/opt/ids/machine_bloque.csv"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([victim_host, blocked_ip, timestamp])

def monitor_alerts(file_path, ssh_user):
    watched_attacks = {"DDoS", "SQLI", "BRUTEFORCE"}
    try:
        with open(file_path, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue
                parts = line.strip().split(",")
                if len(parts) < 6:
                    continue
                attack_type, attacker_ip, victim_ip, _, _, severity = parts
                if severity == "HAUTE" and attack_type in watched_attacks:
                    block_ip(victim_ip, attacker_ip, ssh_user)
    except KeyboardInterrupt:
        print("[!] Script stopped")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    monitor_alerts("/opt/ids/alertessiem.csv", "root")
