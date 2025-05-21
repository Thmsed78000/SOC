import pandas as pd, re, time, os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta

chemin_fichier_log = "/var/log/remote_network.log"
chemin_fichier_alertes = "/opt/ids/alertes.csv"
chemin_fichier_alertes_siem = "/opt/ids/alertessiem.csv"

for fichier in [chemin_fichier_alertes, chemin_fichier_alertes_siem]:
    if not os.path.exists(fichier):
        with open(fichier, 'w') as f:
            f.write("type_attaque,ip_src,ip_dst,port,date,niveau\n")

dernieres_alertes = {}
alerte_delai = timedelta(seconds=1)

def charger_logs(fichier, ligne_depart):
    colonnes = ['temps', 'ip_src', 'ip_dst', 'proto', 'port_src', 'port_dst', 'longueur_trame']
    logs = []
    fichier.seek(ligne_depart)
    for ligne in fichier:
        infos_log = extraire_infos_log(ligne)
        if infos_log and infos_log['ip_src'] != "192.168.1.231":
            logs.append(infos_log)
    return pd.DataFrame(logs, columns=colonnes), fichier.tell()

def extraire_infos_log(ligne):
    motif = r'(?P<temps>[\d\.-]+T[\d\:\.-]+).*?\"(?P<ip_src>[\d\.]+)\",\"(?P<ip_dst>[\d\.]+)\",\"(?P<proto>\d+)\",\"(?P<port_src>\d*?)\",\"(?P<port_dst>\d*?)\".*?,\"(?P<longueur_trame>\d+)\"'
    correspondance = re.match(motif, ligne)
    return correspondance.groupdict() if correspondance else None

def ecrire_alerte_siem(type_attaque, ip_src, ip_dst, port, date, niveau):
    cle_direct, cle_inverse = (type_attaque, ip_src, ip_dst, port), (type_attaque, ip_dst, ip_src, port)
    date_alerte = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S")
    if cle_direct in dernieres_alertes or cle_inverse in dernieres_alertes:
        return
    dernieres_alertes[cle_direct] = date_alerte
    with open(chemin_fichier_alertes_siem, 'a') as f:
        f.write(f"{type_attaque},{ip_src},{ip_dst},{port},{date},{niveau}\n")

def detecter_scan_ia(df, seuil=100):
    df_ports = df.groupby('ip_src')['port_dst'].nunique().reset_index(name='ports_touches')
    df = df.merge(df_ports, on='ip_src', how='left')
    standardiseur = StandardScaler()
    df_normalise = standardiseur.fit_transform(df[['port_src', 'port_dst', 'proto', 'longueur_trame', 'ports_touches']])
    modele = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    modele.fit(df_normalise)
    df['anomalie_scan'] = modele.predict(df_normalise)
    return df[(df['anomalie_scan'] == -1) & (df['ports_touches'] > seuil)]

def detecter_ddos_ia(df, seuil=10000):
    df_requetes = df.groupby(['ip_src', 'port_dst']).size().reset_index(name='requetes_envoyees')
    df = df.merge(df_requetes, on=['ip_src', 'port_dst'], how='left')
    df = df[df['port_dst'] != 22]
    standardiseur = StandardScaler()
    df_normalise = standardiseur.fit_transform(df[['port_src', 'port_dst', 'proto', 'longueur_trame', 'requetes_envoyees']])
    modele = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    modele.fit(df_normalise)
    df['anomalie_ddos'] = modele.predict(df_normalise)
    return df[(df['anomalie_ddos'] == -1) & (df['requetes_envoyees'] > seuil)]

def surveiller_logs():
    ligne_depart = 0
    df_total = pd.DataFrame(columns=['temps', 'ip_src', 'ip_dst', 'proto', 'port_src', 'port_dst', 'longueur_trame'])
    with open(chemin_fichier_log, 'r') as fichier:
        while True:
            nouvelles_donnees, ligne_depart = charger_logs(fichier, ligne_depart)
            if not nouvelles_donnees.empty:
                df_total = pd.concat([df_total, nouvelles_donnees], ignore_index=True).dropna()
                alertes_scan, alertes_ddos = detecter_scan_ia(df_total), detecter_ddos_ia(df_total)
                for _, ligne in alertes_scan.iterrows():
                    ecrire_alerte_siem("SCAN", ligne['ip_src'], ligne['ip_dst'], "", ligne['temps'], "MOYENNE")
                for _, ligne in alertes_ddos.iterrows():
                    ecrire_alerte_siem("DDoS", ligne['ip_src'], ligne['ip_dst'], ligne['port_dst'], ligne['temps'], "HAUTE")
            time.sleep(1)

surveiller_logs()
