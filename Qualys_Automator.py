import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET
import os
import pdfplumber
import re

#filtro per eliminare gli errori di TLS
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

#definizione delle variabili globali
BASE_URL = "BASE URL QUALYS"
AUTH = ("USERNAME", "PASSWORD")
REPORTIR = ""
INCIDENT = ""
OPTION_PROFILE_ID = {
    "INTERNAL": "4008187",
    "EXTERNAL": "4008184",
}
ASSETS_GROUP_ID = {
    "INTERNAL": "6985420", # ALL-IP_INTERNAL_UPDATE-09102023
    "EXTERNAL": "7035486", # AG_ALL-IP_EXTERNAL_UPDATE_20122023
}
EXCLUDED_IPS = [
    "10.0.0.0","10.1.1.1",
]

HEADERS = {
    "X-Requested-With": "Curl",
}

#funzione per creare la variabile globale REPORTIR
def name_report(prompt):
    global REPORTIR
    REPORTIR = input(prompt) 
    

#funzione per effettuare una richiesta HTTP
def make_request(method, url, data=None, auth=None):
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, auth=auth, verify=False)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, data=data, auth=auth, verify=False)
        else:
            raise ValueError(f"Metodo HTTP non supportato: {method}")

        response.raise_for_status()  # Genera un'eccezione per gli errori HTTP
        return response
    except requests.exceptions.HTTPError as http_err:
        print(f"Errore HTTP: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Errore durante la richiesta: {err}")
    except ValueError as val_err:
        print(val_err)
    except Exception as e:
        print(f"Errore non gestito: {e}")

#funzione per leggere le CVE da un file
def read_cve_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            cve_list = [line.strip() for line in file.readlines()]
            cve_list = [cve.replace('\r', '') for cve in cve_list]  # Rimuove il carattere di ritorno a capo
        return cve_list
    except FileNotFoundError:
        print(f"Il file {file_path} non esiste.")
        return []
    except Exception as e:
        print(f"Errore durante la lettura del file: {e}")
        return []


#funzione per creare una dynamic list
def create_dynamiclist(cve_list, auth):
    endpoint = "/api/2.0/fo/qid/search_list/dynamic/"
    full_url = f"{BASE_URL}{endpoint}"

    data = {
        "action": "create",
        "title": "Bollettino Dynamic Test",
        "global": "1",
        "cve_ids_filter": "1",
        "cve_ids": ",".join(cve_list),
    }

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        dynamic_list_id = root.find(".//VALUE").text
        return dynamic_list_id
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None

#funzione per mostrare i QIDs di una Dynamic List
def show_Qid_dynamiclist(auth, dynamic_list_id):
    endpoint = f"/api/2.0/fo/qid/search_list/dynamic/?action=list&ids={dynamic_list_id}"
    full_url = f"{BASE_URL}{endpoint}"

    response = make_request("GET", full_url, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        qid_set = {qid.text.strip() for qid in root.findall(".//QID")}
        return qid_set
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None

#funzione per verificare il tipo di scansione per un QID
def check_qid_scan_type(auth, qid, scan_type):
    try:
        endpoint = f'/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid}&details=None&discovery_method={scan_type}'
        full_url = f"{BASE_URL}{endpoint}"

        response = make_request("GET", full_url, auth=auth)

        if response and response.status_code == 200:
            root = ET.fromstring(response.content)
            idTag = root.find(".//ID")
            return idTag.text if idTag is not None else None
        else:
            print(f"Il QID {qid} non prevede il tipo di scansione {scan_type}.")
            return None
    except Exception as e:
        print(f"Errore durante la verifica del tipo di scansione per il QID {qid}: {e}")
        return None

#funzione per eliminare una dynamic list
def delete_dynamiclist(auth, dynamic_list_id):
    endpoint = f'/api/2.0/fo/qid/search_list/dynamic/'
    full_url = f"{BASE_URL}{endpoint}"
    data = {"action": "delete", "id": dynamic_list_id}

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        print(f"La dynamic list {dynamic_list_id} è stata cancellata con successo")
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")

#funzione per creare una static list
def create_static_list(auth, qid_scan, authentication=False):
    endpoint = "/api/2.0/fo/qid/search_list/static/"
    full_url = f"{BASE_URL}{endpoint}"

    if qid_scan:
        qid_scan_str = ",".join(qid_scan)
       

        data = {
            "action": "create",
            "title": f"SL_{REPORTIR}_{INCIDENT}",
            "global": "1",
            "qids": f"{qid_scan_str}",
        }

        if authentication :
            data["title"] = f"SL_{REPORTIR}_{INCIDENT}_AUTH"

    else:
        print("Errore: Nessun QID trovato")
        exit()

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        static_list_id = root.find(".//VALUE").text
        return static_list_id
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")

#funzione per aggiornare OptionProfile Esterna
def update_OptionProfie_External(auth, static_list_id):
    endpoint = "/api/2.0/fo/subscription/option_profile/vm/"
    full_url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "update",
        "title": f"OP_{REPORTIR}_{INCIDENT}_EXTERNAL",
        "vulnerability_detection": "custom",
        "custom_search_list_ids": [static_list_id],
        "id": f"{OPTION_PROFILE_ID['EXTERNAL']}",
    }

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(root.find(".//TEXT").text)
        return None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None

#funzione per aggiornare OptionProfile Interna
def update_OptionProfie_Internal(auth, static_list_id, authentication=False):
    endpoint = "/api/2.0/fo/subscription/option_profile/vm/"
    full_url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "update",
        "title": f"OP_{REPORTIR}_{INCIDENT}_INTERNAL",
        "vulnerability_detection": "custom",
        "custom_search_list_ids": [static_list_id],
        "id": f"{OPTION_PROFILE_ID['INTERNAL']}",
        "authentication": "",
    }
    if authentication is True:
        data["authentication"] = "Windows,Unix"

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(root.find(".//TEXT").text)
        return None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None
#funzione per confermare il lancio della scansione    
def confirm_scan_launch():
    while True:
        choice = input("Vuoi lanciare la scansione? (sì/no): ").lower()
        if choice in ['sì', 'si', 's', 'yes', 'y']:
            return True
        elif choice in ['no','n']:
            return False
        else:
            print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")
            
#funzione per lanciare la scansione interna
def launch_scan_internal(auth):
    endpoint = "/api/2.0/fo/scan/"
    full_url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "launch",
        "scan_title": f"Scan_{REPORTIR}_INTERNAL",
        "option_id": f"{OPTION_PROFILE_ID['INTERNAL']}",
        "target_from" : "assets",
        "scanners_in_ag" : "1",
        "asset_group_ids" : f"{ASSETS_GROUP_ID['INTERNAL']}",
        "priority" : "0",
        "exclude_ip_per_scan" : ",".join(EXCLUDED_IPS),
        }
    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        scanId = root.find(".//ITEM[KEY='ID']/VALUE")
        print(f"Scansione interna lanciata con successo con ID: {scanId.text}")
        return scanId.text if scanId is not None else None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
    return None
#funzione che lancia la scansione esterna
def launch_scan_external(auth):
    endpoint = "/api/2.0/fo/scan/"
    full_url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "launch",
        "scan_title": f"Scan_{REPORTIR}_EXTERNAL",
        "option_id": f"{OPTION_PROFILE_ID['EXTERNAL']}",
        "target_from" : "assets",
        "asset_group_ids" : f"{ASSETS_GROUP_ID['EXTERNAL']}",
        "priority" : "0",
        }
    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        scanId = root.find(".//ITEM[KEY='ID']/VALUE")
        print(f"Scansione esterna lanciata con successo con ID: {scanId.text}")
        return scanId.text if scanId is not None else None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
    return None

def estrai_cve_da_pdf(pdf_path):
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_set = set()

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            cve_list = re.findall(cve_pattern, text)
            cve_set.update(cve_list)

    return cve_set

def extract_first_id_from_pdf(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            # Utilizziamo una regex per trovare il primo match del pattern specificato
            id_match = re.search(r'\bIR\d{6,8}EW\b', text)
            report_id= id_match.group()
            print(f"Il bollettino è il {report_id}")
            if id_match:
                return report_id
    return None  # Restituiamo None se non viene trovato alcun ID

def salva_cve_su_file(cve_set, output_file):
    with open(output_file, 'w') as f:
        for cve in cve_set:
            f.write(f"{cve}\n")

#funzione per eseguire il codice
if __name__ == "__main__":
    INCIDENT = input("Inserisci il numero di incidente: ")
    print(f"Vuoi procedere ad una estrazione delle CVE da un file PDF? (sì/no): ")
    choice = input().lower()
    if choice in ['sì', 'si', 's', 'yes', 'y']:

        pdf_files = [file for file in os.listdir() if file.endswith('.pdf')]
        if pdf_files:
            pdf_path = pdf_files[0]
            print(f"Trovato il file PDF: {pdf_path}")

            REPORTIR = extract_first_id_from_pdf(pdf_path)
            cve_list = estrai_cve_da_pdf(pdf_path)

            if cve_list:
                output_file = 'cve_list.txt'
                salva_cve_su_file(cve_list, output_file)
                num_cve = len(cve_list)
                print(f"Le CVE sono state estratte con successo e salvate in {output_file}.")
                print(f"Numero totale di CVE uniche estratte: {num_cve}")
            else:
                print("Nessuna CVE trovata nel file PDF.")
        else:
            print("Nessun file PDF trovato nella directory corrente.")
    elif choice in ['no', 'n']:
        REPORTIR = input("Inserisci il nome del bollettino: ")
        cve_list = read_cve_from_file("cve_list.txt")
    else:
        print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")
        exit()
    dynamic_id = create_dynamiclist(cve_list, AUTH)
    qid_set = show_Qid_dynamiclist(AUTH, dynamic_id)
    if not qid_set:
        print("Errore: Nessun QID è presente nella KnowledgeBase di Qualys.")
        delete_dynamiclist(AUTH, dynamic_id)
        exit()

    #print(f'QID associati alla dynamic list: {qid_set}')

    authenticatedOnly = [qid for qid in qid_set if check_qid_scan_type(AUTH, qid, 'AuthenticatedOnly')]
    print(f"AuthenticatedOnly: {authenticatedOnly}")
    qid_set = qid_set - set(authenticatedOnly)
    remoteOnly = [qid for qid in qid_set if check_qid_scan_type(AUTH, qid, 'RemoteOnly')]
    print(f"RemoteOnly: {remoteOnly}")
    qid_set = qid_set - set(remoteOnly)
    remoteAndAuth = [qid for qid in qid_set if check_qid_scan_type(AUTH, qid, 'RemoteAndAuthenticated')]
    print(f"RemoteAndAuth: {remoteAndAuth}")
    qid_set = qid_set - set(remoteAndAuth)

    
    # Se possibile scansione remota e autenticata
    if (remoteOnly and  authenticatedOnly) or remoteAndAuth:
        print(f"Sono presenti QIDs sia remoti che autenticati \nSi vuole procedere con una scansione autenticata? (sì/no): ")
        choice = input().lower()
        if choice in ['sì', 'si', 's', 'yes', 'y']:
            print(f"Procedendo alla creazione delle static list per la scansioni autenticate.")
            qid_scan = remoteAndAuth + authenticatedOnly + remoteOnly
            static_list_id = create_static_list(AUTH, qid_scan, authentication=True)
            if static_list_id:
                print(f"Static list creata con successo con ID: {static_list_id}")
            update_OptionProfie_Internal(AUTH, static_list_id, authentication=True)
            qid_scan = remoteAndAuth + remoteOnly
            static_list_id = create_static_list(AUTH, qid_scan)
            if static_list_id:
                print(f"Static list creata con successo con ID: {static_list_id}") 
            update_OptionProfie_External(AUTH, static_list_id)
            delete_dynamiclist(AUTH, dynamic_id)
            if confirm_scan_launch():
                launch_scan_internal(AUTH)
                launch_scan_external(AUTH)
                exit()
            else:
                print("Scansioni Autenticate non lanciate.")
                exit()
        if choice in ['no', 'n'] and remoteAndAuth or remoteOnly:
            print(f"Procedendo alla creazione delle static list per la scansioni remote.")
            qid_scan = remoteAndAuth + remoteOnly
            static_list_id = create_static_list(AUTH, qid_scan)
            if static_list_id:
                print(f"Static list creata con successo con ID: {static_list_id}")
            delete_dynamiclist(AUTH, dynamic_id)
            update_OptionProfie_Internal(AUTH, static_list_id)
            update_OptionProfie_External(AUTH, static_list_id)
            if confirm_scan_launch():
                launch_scan_internal(AUTH)
                launch_scan_external(AUTH)
                exit()
            else:  
                print("Scansioni non lanciate.")
                delete_dynamiclist(AUTH, dynamic_id)
                exit()
        else:
            print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")
            exit()
    
    #se possibile solo scansione remota 
    elif remoteOnly:
        print(f"I QIDs sono solo remote \nProcedendo alla creazione della static list per le scansioni remota.")
        qid_scan = remoteOnly + remoteAndAuth
        static_list_id = create_static_list(AUTH, qid_scan)
        if static_list_id:
            print(f"Static list creata con successo con ID: {static_list_id}")
        delete_dynamiclist(AUTH, dynamic_id)
        update_OptionProfie_Internal(AUTH, static_list_id)
        update_OptionProfie_External(AUTH, static_list_id)
        if confirm_scan_launch():
            launch_scan_internal(AUTH)
            launch_scan_external(AUTH)
            exit()
        else:
            print("Scansioni non lanciate.")
            delete_dynamiclist(AUTH, dynamic_id)
            exit()
    #se possibile solo scansione autenticata
    elif authenticatedOnly:
        print(f"I QIDs sono solo autenticati \nProcedendo alla creazione delle static list per la scansione autenticata.")
        qid_scan = authenticatedOnly
        static_list_id = create_static_list(AUTH, qid_scan, authentication=True)
        if static_list_id:
            print(f"Static list creata con successo con ID: {static_list_id}")
        delete_dynamiclist(AUTH, dynamic_id)
        update_OptionProfie_Internal(AUTH, static_list_id, authentication=True)
        if confirm_scan_launch():
            launch_scan_internal(AUTH)
            exit()
        else:
            print("Scansioni Autenticate non lanciate.")
            exit()
