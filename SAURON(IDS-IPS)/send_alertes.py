import requests, time, os

# Configuration
SIEM_API_URL = "http://10.241.239.12/api/upload_csv.php"
ALERTS_FILE = "/opt/ids/alertessiem.csv"
BLOCKED_IPS_FILE = "/opt/ids/machine_bloque.csv"
SLEEP_TIME = 10  # Intervalle d'envoi en secondes

def get_last_line_sent(file_path):
    """ Récupère l'index de la dernière ligne envoyée dans un fichier de suivi. """
    path = file_path + ".last_line_sent"
    if os.path.exists(path):
        with open(path, "r") as f: return int(f.read().strip())
    return 0

def update_last_line_sent(file_path, line_number):
    """ Met à jour l'index de la dernière ligne envoyée pour un fichier spécifique. """
    with open(file_path + ".last_line_sent", "w") as f: f.write(str(line_number))

def send_csv_file(file_path, field_name):
    """ Envoie les nouvelles lignes du fichier CSV. """
    if not os.path.exists(file_path):
        print(f"_ Le fichier {file_path} n'existe pas.")
        return
    with open(file_path, "r") as f: lines = f.readlines()
    last_line_sent = get_last_line_sent(file_path)
    new_lines = lines[last_line_sent:]
    if not new_lines:
        print(f"Il n'y a pas de nouvelles alertes dans {file_path}. Aucun envoi.")
        return
    try:
        files = {field_name: (os.path.basename(file_path), "".join(new_lines), "text/csv")}
        response = requests.post(SIEM_API_URL, files=files)
        print(f"__ Réponse de l'API pour {file_path} : {response.status_code}, {response.text}")
        if response.status_code == 200:
            update_last_line_sent(file_path, last_line_sent + len(new_lines))
    except Exception as e:
        print(f"__ Erreur lors de l'envoi de {file_path} : {e}")

# Boucle d'envoi périodique
if __name__ == "__main__":
    while True:
        send_csv_file(ALERTS_FILE, "file1")
        send_csv_file(BLOCKED_IPS_FILE, "file2")
        time.sleep(SLEEP_TIME)
