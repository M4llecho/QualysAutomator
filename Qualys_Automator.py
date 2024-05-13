import os
import re
import requests
from urllib3.exceptions import InsecureRequestWarning
import pdfplumber
import xml.etree.ElementTree as ET
from prettytable import PrettyTable

## --------------------------------- Parte 0: Variabili Globali Qualys--------------------------------- ##
REPORTIR = ""
INCIDENT = ""
OPTION_PROFILE_ID = {
    "INTERNAL": "4008187",
    "EXTERNAL": "4008184",
}
ASSETS_GROUP_ID = {
    "INTERNAL": "6985420",  # ALL-IP_INTERNAL_UPDATE-09102023
    "EXTERNAL": "7035486",  # AG_ALL-IP_EXTERNAL_UPDATE_20122023
}
EXCLUDED_IPS = [
    "10.88.4.57", "10.88.4.58", "10.88.4.63", "10.88.4.64", "10.88.4.92", "10.88.4.111", "10.88.4.132", "10.88.4.139",
    "10.88.4.140", "10.88.36.177",
    "10.88.192.236", "10.88.192.240", "10.88.192.245", "10.88.192.251", "10.128.176.47", "10.128.177.51",
    "10.128.190.75", "10.128.190.213", "10.128.190.214",
    "10.128.191.229", "10.128.191.240", "10.129.77.119", "10.129.155.74", "10.129.155.204", "10.129.155.213",
    "10.131.152.143", "10.131.157.45",
    "10.131.157.46", "10.132.195.246", "10.132.195.248", "10.132.195.250", "10.132.195.254", "10.132.236.36",
    "10.139.72.28", "10.139.74.166", "10.139.85.22",
    "10.139.85.24", "10.139.85.26", "10.139.85.28", "10.139.85.63", "10.139.85.83", "10.139.85.84", "10.139.85.89",
    "10.140.216.82", "10.144.4.27", "10.144.4.114",
    "10.144.4.135", "10.156.21.21", "10.157.97.240", "10.157.97.243", "10.158.67.230", "10.158.232.111", "10.159.35.97",
    "10.159.35.100", "10.159.35.108",
    "10.160.82.93", "10.168.22.57", "10.180.124.7", "10.180.124.35", "10.182.46.133"
]

## --------------------------------- Parte 1: Gestione richieste HTTP --------------------------------- ##

BASE_URL = "https://BASEURL"
AUTH = ("USERNAME", "PASSWORD")
HEADERS = {
    "X-Requested-With": "Curl",
}

# Disabilità i warning relativi ai certificati SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# Funzione per effettuare una richiesta HTTP
def submit_request(method, url, data=None, auth=None):
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, auth=AUTH, verify=False)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, data=data, auth=AUTH, verify=False)
        else:
            raise ValueError(f"Invalid method: {method}")

        response.raise_for_status()  # Lanciamo un'eccezione se il codice di stato HTTP non è 200
        return response
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
    except ValueError as v_err:
        print(f"An error occurred: {v_err}")
    except Exception as e:
        print(f"An error occurred: {e}")


## --------------------------------- Part 2: Gestione parsing PDF e lettura e scrittura TXT --------------------------------- ##

# Funzione per estrarre le CVE da un file PDF 
def extract_cve_from_pdf(pdf_path):
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_set = set()

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            cve_list = re.findall(cve_pattern, text)
            cve_set.update(cve_list)

    return cve_set


# Funzione per leggere le CVE da un file TXT
def read_cve_from_text(file_path):
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


# Funzione per estrarre il primo ID di un bollettino da un file PDF
def extract_report_id(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            # Utilizziamo una regex per trovare il primo match del pattern specificato
            id_match = re.search(r'\bIR\d{6,8}EW\b', text)
            report_id = id_match.group()
            print(f"Il bollettino è il {report_id}")
            if id_match:
                return report_id
    return None  # Restituiamo None se non viene trovato alcun ID


# Funzione per salvare le CVE in un file di testo
def save_pdf_to_file(cve_set, output_file):
    with open(output_file, 'w') as f:
        for cve in cve_set:
            f.write(f"{cve}\n")


##---------------------------------- Part 3: Gestione TEMPORAL score --------------------------------- ##

# Funzione per calcolare il punteggio TEMPORAL
def define_TEMPORAL_score(cvss2_temp, cvss3_temp):
    if cvss3_temp == 10:
        return "Critical"
    elif 9.0 <= cvss3_temp < 10:
        return "High"
    elif 6.0 <= cvss3_temp < 9:
        return "Medium"
    elif 0.1 <= cvss3_temp < 6:
        return "Low"
    elif cvss3_temp == 0:
        return "None"
    else:
        if cvss2_temp == 10:
            return "Critical"
        elif 9.0 <= cvss2_temp < 10:
            return "High"
        elif 6.0 <= cvss2_temp < 9:
            return "Medium"
        elif 0.1 <= cvss2_temp < 6:
            return "Low"
        elif cvss2_temp == 0:
            return "None"
        else:
            return "None"


# Funzione per raggruppare i QIDs per severità
def define_qids_per_severity(qids_info):
    qids_critical = []
    qids_high = []
    qids_medium = []
    qids_low = []
    qids_none = []
    for qid, info in qids_info.items():
        severity = info["severity"]
        if severity == "Critical":
            qids_critical.append(qid)
        elif severity == "High":
            qids_high.append(qid)
        elif severity == "Medium":
            qids_medium.append(qid)
        elif severity == "Low":
            qids_low.append(qid)
        elif severity == "None":
            qids_none.append(qid)

    table = PrettyTable(["Severity", "QIDs"])
    table.add_row(["Critical", qids_critical])
    table.add_row(["High", qids_high])
    table.add_row(["Medium", qids_medium])
    table.add_row(["Low", qids_low])
    table.add_row(["None", qids_none])

    print(table)

    return qids_critical, qids_high, qids_medium, qids_low, qids_none


## --------------------------------- Parte 4: Gestione Dynamic e Static List ----------------------------- ##

# Funzione per la creazione di una dynamic list
def create_dynamic_list(cve_list):
    endpoint = "/api/2.0/fo/qid/search_list/dynamic/"
    url = f"{BASE_URL}{endpoint}"

    data = {
        "action": "create",
        "title": "CVEs to QIDs",
        "global": "1",
        "cve_ids_filter": "1",
        "cve_ids": ",".join(cve_list)
    }

    response = submit_request("POST", url, data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        dynamic_list_id = root.find(".//VALUE").text
        print(f"Dynamic list creata con ID: {dynamic_list_id}")
        return dynamic_list_id
    else:
        print("Errore nella creazione della dynamic list.")
        return None


# Funzione per mostrare i QIDs di una dynamic list
def show_qids_from_dynamic_list(dynamic_list_id):
    endpoint = f"/api/2.0/fo/qid/search_list/dynamic/?action=list&ids={dynamic_list_id}"
    url = f"{BASE_URL}{endpoint}"

    response = submit_request("GET", url)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        qid_set = {qid.text.strip() for qid in root.findall(".//QID")}
        return qid_set
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None


# Funzione per eliminare una dynamic list
def delete_dynamic_list(dynamic_list_id):
    endpoint = "/api/2.0/fo/qid/search_list/dynamic/"
    url = f"{BASE_URL}{endpoint}"

    data = {
        "action": "delete",
        "id": dynamic_list_id
    }

    response = submit_request("POST", url, data)

    if response.status_code == 200:
        print(f"Dynamic list with ID {dynamic_list_id} deleted")
    else:
        print(f"Error deleting dynamic list with ID {dynamic_list_id}")


def create_static_list(qids_scan, authentication=False):
    endpoint = "/api/2.0/fo/qid/search_list/static/"
    url = f"{BASE_URL}{endpoint}"

    if qids_scan:
        qid_scan_str = ",".join(qids_scan)

        data = {
            "action": "create",
            "title": f"SL_{REPORTIR}_{INCIDENT}",
            "global": "1",
            "qids": f"{qid_scan_str}",
        }

        if authentication:
            data["title"] = f"SL_{REPORTIR}_{INCIDENT}_AUTH"

    else:
        print("Errore: Nessun QID trovato")
        exit()

    response = submit_request("POST", url, data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        static_list_id = root.find(".//VALUE").text
        return static_list_id
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")


## --------------------------------- Parte 5: Gestione QIDs e KnowledgeBase  --------------------------------- ##

# Funzione per ottenere le informazioni di un QID
def get_qid_info(qid):
    endpoint = f"/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&ids={qid}"
    url = f"{BASE_URL}{endpoint}"

    qid_data = {}

    response = submit_request("GET", url)

    if response and response.status_code == 200:
        root = ET.fromstring(response.content)
        for vuln in root.iter('VULN'):
            #parsing CVEs
            cve_elements = vuln.findall('.//CVE_LIST/CVE/ID')
            cve_list = [cve.text for cve in cve_elements]

        #parsing del cvss3 temporal
        cvss3_temporal_element = vuln.find('.//CVSS_V3/TEMPORAL')
        if cvss3_temporal_element is not None:
            cvss3_temporal = float(cvss3_temporal_element.text)
        else:
            cvss3_temporal = None

        #parsin del cvss2 temporal
        cvss2_temporal_element = vuln.find('.//CVSS/TEMPORAL')
        if cvss2_temporal_element is not None:
            cvss2_temporal = float(cvss2_temporal_element.text)
        else:
            cvss2_temporal = None

        #parsing del valore Remote
        remote = vuln.find('.//REMOTE').text

        #parsing del valore auth
        auth_type = vuln.find('.//DISCOVERY/AUTH_TYPE_LIST/AUTH_TYPE')
        if auth_type is not None:
            auth_type_text = auth_type.text
            if auth_type_text == "Unix":
                auth = {"Unix": True}
            else:
                auth = {"Unix": False}
            if auth_type_text == "Windows":
                auth["Windows"] = True
            else:
                auth["Windows"] = False
        else:
            auth = {"Unix": False, "Windows": False}

        TEMPORAL_severity = define_TEMPORAL_score(cvss2_temporal, cvss3_temporal) if cvss2_temporal and cvss3_temporal else None

    qid_data[qid] = {
        "CVEs": cve_list,
        "CVSS3 Temporal": cvss3_temporal,
        "CVSS2 Temporal": cvss2_temporal,
        "Remote": remote,
        "authentication": auth,
        "severity": TEMPORAL_severity
    }
    #able = PrettyTable(["QID", "CVEs", "CVSS3 Temporal", "CVSS2 Temporal", "Remote", "Authentication", "Severity"])
    #for qid, info in qid_data.items():
    #    table.add_row(
    #       [qid, info["CVEs"], info["CVSS3 Temporal"], info["CVSS2 Temporal"], info["Remote"], info["authentication"],
    #         info["severity"]])

    #print(table)

    return qid_data


# Funzione per ottenere i QIDs scansionabili in base al tipo di scansione

def define_qids_for_scan_type(qid_info, qids_scansionabili):
    qids_authenticated_only = []
    qids_remote_only = []
    qids_remote_and_authenticated = []
    for qid in qids_scansionabili:
        requires_unix_auth = qid_info[qid]["authentication"].get("Unix", True)
        requires_windows_auth = qid_info[qid]["authentication"].get("Windows", True)
        requires_remote = qid_info[qid]["Remote"] == "1"

        if (requires_unix_auth or requires_windows_auth) and requires_remote:
            qids_remote_and_authenticated.append(qid)
        elif (requires_unix_auth or requires_windows_auth) and not requires_remote:
            qids_authenticated_only.append(qid)
        elif not (requires_unix_auth or requires_windows_auth) and requires_remote:
            qids_remote_only.append(qid)

    table = PrettyTable(["Scan Type", "QIDs"])
    table.add_row(["Remote and Authenticated", qids_remote_and_authenticated])
    table.add_row(["Authenticated only", qids_authenticated_only])
    table.add_row(["Remote only", qids_remote_only])

    # Stampa della tabella
    print(table)

    return qids_remote_and_authenticated, qids_authenticated_only, qids_remote_only


## ------------------------------- Part 6: Gestione Option Profile Interna e Esterna------------------------------- ##

# Funzione per aggiornare l'Option Profile esterno
def update_option_profile_external(static_list_id):
    endpoint = "/api/2.0/fo/subscription/option_profile/vm/"
    url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "update",
        "title": f"OP_{REPORTIR}_{INCIDENT}_EXTERNAL",
        "vulnerability_detection": "custom",
        "custom_search_list_ids": [static_list_id],
        "id": f"{OPTION_PROFILE_ID['EXTERNAL']}",
    }

    response = submit_request("POST", url, data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(root.find(".//TEXT").text)
        return None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None


# Funzione per aggiornare l'Option Profile interno
def update_option_profile_internal(static_list_id, authentication=False):
    endpoint = "/api/2.0/fo/subscription/option_profile/vm/"
    url = f"{BASE_URL}{endpoint}"
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
        data["title"] = f"OP_AUTH_{REPORTIR}_{INCIDENT}_INTERNAL"

    response = submit_request("POST", url, data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(root.find(".//TEXT").text)
        return None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None


#------------------------------- Part 7: Gestione lancio Scansioni --------------------------------- #

# Funzione per lanciare una scansione interna
def run_internal_scan(authentication=False):
    endpoint = "/api/2.0/fo/scan/"
    url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "launch",
        "scan_title": f"Scan_{REPORTIR}_{INCIDENT}_INTERNAL",
        "option_id": f"{OPTION_PROFILE_ID['INTERNAL']}",
        "target_from": "assets",
        "scanners_in_ag": "1",
        "asset_group_ids": f"{ASSETS_GROUP_ID['INTERNAL']}",
        "priority": "0",
        "exclude_ip_per_scan": ",".join(EXCLUDED_IPS),
    }
    if authentication is True:
        data["title"] = f"Scan_AUTH_{REPORTIR}_{INCIDENT}_INTERNAL"

    response = submit_request("POST", url, data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        scanId = root.find(".//ITEM[KEY='ID']/VALUE")
        print(f"Scansione interna lanciata con successo con ID: {scanId.text}")
        return scanId.text if scanId is not None else None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
    return None


# Funzione per lanciare una scansione esterna
def run_external_scan():
    endpoint = "/api/2.0/fo/scan/"
    url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "launch",
        "scan_title": f"Scan_{REPORTIR}_EXTERNAL",
        "option_id": f"{OPTION_PROFILE_ID['EXTERNAL']}",
        "target_from": "assets",
        "asset_group_ids": f"{ASSETS_GROUP_ID['EXTERNAL']}",
        "priority": "0",
    }
    response = submit_request("POST", data=data)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        scanId = root.find(".//ITEM[KEY='ID']/VALUE")
        print(f"Scansione esterna lanciata con successo con ID: {scanId.text}")
        return scanId.text if scanId is not None else None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
    return None


def confirm_scan_launch():
    while True:
        choice = input("Vuoi lanciare la scansione? (sì/no): ").lower()
        if choice in ['sì', 'si', 's', 'yes', 'y']:
            return True
        elif choice in ['no', 'n']:
            return False
        else:
            print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")

## ------------------------ Parte 8: Testi di chiusura Tickets ---------------------------- ##

def template_no_vulnerabilities_in_scope():
    message = (
        "\n" * 5 +
        "Additional comments (Customer visible):\n"
        "The report contains no HIGH or CRITICAL CVEs for the TEMPORAL Score.\n"
        "The vulnerabilities in the report, which are all medium and low for the TEMPORAL Score, will be analyzed with "
        "the next monthly scan.\n"
        "Regards\n\n"
        "Resolution notes:\n"
        "It is recommended that a backup be made before any remediation action is taken.\n"
    )
    print(message)
    return None

## ------------------------------------- Main --------------------------------------------- ##

if __name__ == "__main__":
    INCIDENT = input("Inserisci il numero di incident: ")
    print(f"Vuoi procedere ad una estrazione delle CVE da un file PDF? (sì/no): ")
    choice = input().lower()
    if choice in ['sì', 'si', 's', 'yes', 'y']:
        pdf_files = [file for file in os.listdir() if file.endswith('.pdf')]
        if pdf_files:
            pdf_path = pdf_files[0]
            print(f"Trovato il file PDF: {pdf_path}")

            REPORTIR = extract_report_id(pdf_path)
            cve_list = extract_cve_from_pdf(pdf_path)

            if cve_list:
                output_file = 'cve_list.txt'
                save_pdf_to_file(cve_list, output_file)
                num_cve = len(cve_list)
                print(f"Le CVE sono state estratte con successo e salvate in {output_file}.")
                print(f"Numero totale di CVE uniche estratte: {num_cve}")
            else:
                print("Nessuna CVE trovata nel file PDF.")
        else:
            print("Nessun file PDF trovato nella directory corrente.")

    elif choice in ['no', 'n']:
        REPORTIR = input("Inserisci il numero di report IR: ")
        cve_list = read_cve_from_text("cve_list.txt")
    else:
        print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")
        exit()
    dynamic_list_id = create_dynamic_list(cve_list)
    qids_set = show_qids_from_dynamic_list(dynamic_list_id)
    print(f"QIDs trovati nella dynamic list: {qids_set}")
    delete_dynamic_list(dynamic_list_id)
    if not qids_set:
        print("Nessun QID trovato nella dynamic list.")
        exit()
    qids_info = {}
    for qid in qids_set:
        qid_info = get_qid_info(qid)
        qids_info.update(qid_info)

    qids_critical, qids_high, qids_medium, qids_low, qids_none = define_qids_per_severity(qids_info)

    qids_scansionabili = qids_critical + qids_high

    if not qids_scansionabili:
        print("Non è stato trovato nessun QIDs di severità Critical o High per il TEMPORAL Score, non è necessario proseguire con le scansioni.")
        template_no_vulnerabilities_in_scope()
        exit()

    qids_remote_and_authenticated, qids_authenticated_only, qids_remote_only = define_qids_for_scan_type(qids_info,qids_scansionabili)

    if qids_remote_and_authenticated or (qids_remote_only and qids_authenticated_only):
        print(
            f"Sono presenti QIDs sia remoti che autenticati \nSi vuole procedere con una scansione autenticata? (sì/no): ")
        choice = input().lower()
        if choice in ['sì', 'si', 's', 'yes', 'y']:
            print(f"Procedendo alla creazione della static list per la scansioni autenticate.")
            qids_inscope = qids_remote_and_authenticated + qids_authenticated_only + qids_remote_only
            static_list_id = create_static_list(qids_inscope, authentication=True)
            if static_list_id is None:
                print(f"Errore nella creazione della static list per la scansione autenticata interna.")
                exit()
            print(f"Static list interna creata con successo con ID: {static_list_id}")
            update_option_profile_internal(static_list_id, authentication=True)
            qids_inscope = qids_remote_and_authenticated + qids_remote_only
            static_list_id = create_static_list(qids_inscope)
            if static_list_id is None:
                print(f"Errore nella creazione della static list per la scansione esterna.")
                exit()
            print(f"Static list esterna creata con successo con ID: {static_list_id}")
            update_option_profile_external(static_list_id)
            if confirm_scan_launch():
                run_internal_scan(authentication=True)
                run_external_scan()
                exit()
            else:
                print("Scansioni Autenticate non lanciate.")
                exit()
        if choice in ['no', 'n'] and qids_remote_and_authenticated or qids_remote_only:
            print(f"Procedendo alla creazione della static list per le scansioni remote.")
            qids_inscope = qids_remote_and_authenticated + qids_remote_only
            static_list_id = create_static_list(qids_inscope)
            if static_list_id:
                print(f"Static list creata con successo con ID: {static_list_id}")
            update_option_profile_internal(static_list_id)
            update_option_profile_external(static_list_id)
            if confirm_scan_launch():
                run_internal_scan()
                run_external_scan()
                exit()
            else:
                print("Scansioni non lanciate.")
                exit()
        else:
            print("Risposta non valida. Per favore, inserisci 'sì' o 'no'.")
            exit()

    elif qids_remote_only:
        print(f"I QIDs sono solo remote \nProcedendo alla creazione della static list per le scansioni remota.")
        static_list_id = create_static_list(qids_remote_only)
        if static_list_id:
            print(f"Static list creata con successo con ID: {static_list_id}")
        update_option_profile_internal(static_list_id)
        update_option_profile_external(static_list_id)
        if confirm_scan_launch():
            run_internal_scan()
            run_external_scan()
            exit()
        else:
            print("Scansioni non lanciate.")
            exit()

    elif qids_authenticated_only:
        print(
            f"I QIDs sono solo autenticati \nProcedendo alla creazione delle static list per la scansione autenticata.")
        qids_inscope = qids_authenticated_only
        static_list_id = create_static_list(qids_inscope, authentication=True)
        if static_list_id is None:
            print(f"Errore nella creazione della static list per la scansione autenticata.")
        print(f"Static list creata con successo con ID: {static_list_id}")
        update_option_profile_internal(static_list_id, authentication=True)
        if confirm_scan_launch():
            run_internal_scan(authentication=True)
            exit()
        else:
            print("Scansioni Autenticate non lanciate.")
            exit()

"""
Il programma è stato progettato per estrarre le CVE da un file PDF, ma è possibile utilizzare un file di testo con le CVE già estratte.
Una volta estratte le CVE, il programma crea una dynamic list con le CVE e ottiene le informazioni sui QIDs relativi alle CVE. 
Successivamente, il programma raggruppa i QIDs per severità e tipo di scansione e crea le static list per le scansioni autenticate e remote.
una volta create le static list, il programma aggiorna gli Option Profile e lancia le scansioni interne ed esterne.  

Work in progress: creazione di template  per la chiusura degli incidents, contententi un breve testo delle analisi e una tabella di tracciamento CVE analizzate.

--Nicolò--
"""
