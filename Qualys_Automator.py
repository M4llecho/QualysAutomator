#Il programma prende la lista di cve estratta tramite l'altro programma (CVE-Extractor) per poi
#creare due profili option profile, uno intenro ed uno esterno con i QID associati alle CVE che
# possono essere scansionate remote only o remote and authenticated.

#se il programma si inceppa eliminare la dynamic list "test_bollettino" su qualys

#NON ELIMINARE MAI LE OPTION PROFILE POICHE' IL SOFTWARE LE ITERA AGGIORNANDOLE DI CONTINUO E NON LE CREA
#DA ZERO COME LE SEARCH LIST

import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET

#filtro per eliminare gli errori di TLS
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

#definizione delle variabili globali
BASE_URL = "https://qualysguard.qg2.apps.qualys.eu"
AUTH = ("USERNAME", "PASSWORD")
REPORTIR = ""

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
def create_static_list2(auth, qid_remote=None, qid_remoteAndAuth=None):
    endpoint = "/api/2.0/fo/qid/search_list/static/"
    full_url = f"{BASE_URL}{endpoint}"

    if qid_remote and qid_remoteAndAuth:
        qid_remote_str = ",".join(qid_remote)
        qid_remoteAndAuth_str = ",".join(qid_remoteAndAuth)

        data = {
            "action": "create",
            "title": f"SL_{REPORTIR}",
            "global": "1",
            "qids": f"{qid_remote_str},{qid_remoteAndAuth_str}",
        }
    elif not qid_remote and qid_remoteAndAuth:
        qid_remoteAndAuth_str = ",".join(qid_remoteAndAuth)

        data = {
            "action": "create",
            "title": f"SL_{REPORTIR}",
            "global": "1",
            "qids": f"{qid_remoteAndAuth_str}",
        }
    elif qid_remote and not qid_remoteAndAuth:
        qid_remote_str = ",".join(qid_remote)

        data = {
            "action": "create",
            "title": f"SL_{REPORTIR}",
            "global": "1",
            "qids": f"{qid_remote_str}",
        }
    elif not qid_remote and not qid_remoteAndAuth:
        print("Errore: Nessun QID trovato per la scansione remota autenticata e/o remota.")
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
        "title": f"OP_{REPORTIR}_EXTERNAL",
        "vulnerability_detection": "custom",
        "custom_search_list_ids": [static_list_id],
        "id": "4008184",
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
def update_OptionProfie_Internal(auth, static_list_id):
    endpoint = "/api/2.0/fo/subscription/option_profile/vm/"
    full_url = f"{BASE_URL}{endpoint}"
    data = {
        "action": "update",
        "title": f"OP_{REPORTIR}_INTERNAL",
        "vulnerability_detection": "custom",
        "custom_search_list_ids": [static_list_id],
        "id": "4008187",
    }

    response = make_request("POST", full_url, data=data, auth=auth)

    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(root.find(".//TEXT").text)
        return None
    else:
        print(f"Errore nella richiesta HTTP: {response.status_code}")
        return None

#funzione per eseguire il codice
if __name__ == "__main__":
    name_report("Codice Bollettino: ")

    cve_list = read_cve_from_file("cve_list.txt")
    dynamic_id = create_dynamiclist(cve_list, AUTH)
    qid_set = show_Qid_dynamiclist(AUTH, dynamic_id)
    if not qid_set:
        print("Errore: Nessun QID associato alla dynamic list.")
        exit()
    print(f'QID associati alla dynamic list: {qid_set}')
    remoteAndAuth = [qid for qid in qid_set if check_qid_scan_type(AUTH, qid, 'RemoteAndAuthenticated')]
    remoteOnly = [qid for qid in qid_set if check_qid_scan_type(AUTH, qid, 'RemoteOnly')]
    print(f"RemoteAndAuth: {remoteAndAuth}")
    print(f"RemoteOnly: {remoteOnly}")
    if remoteAndAuth or remoteOnly:
        static_list_id = create_static_list2(AUTH, remoteOnly, remoteAndAuth)
    else:
        print("Nessun QID prevede scansione RemoteOnly o RemoteAndAuth.")
        delete_dynamiclist(AUTH, dynamic_id)
        exit()
    if static_list_id:
        print(f"Static list creata con successo con ID: {static_list_id}")

    delete_dynamiclist(AUTH, dynamic_id)

    update_OptionProfie_External(AUTH, static_list_id)
    update_OptionProfie_Internal(AUTH, static_list_id)
