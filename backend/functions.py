import requests
import json
import subprocess
from datetime import datetime
import Levenshtein
import ssl
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def safebrowsing_result(url, key):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    payload = {
        "client": {
            "clientId": "beatriz-project",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(endpoint, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        data = response.json()
        if 'matches' in data:
            url_type = {}
            for match in data["matches"]:
                url_type[match['threat']['url']] = match['threatType']
            return {"encontrado": True, "matches": url_type}
        else:
            return {"encontrado": False}
    else:
        return "Erro na requisição"

def replace_letters(domain):
    letter_map = {
    'a': '4',
    'e': '3',
    'i': '1',
    'o': '0',
    's': '5',
    't': '7',
    'g': '9',
    'b': '8'
    }

    substitutions = {}

    for char, substitute in letter_map.items():
        if substitute in domain:
            substitutions[substitute] = char

    if substitutions:
        return {"encontrado": True, "substituicoes": substitutions}
    else:
        return {"encontrado": False}


def special_characters(url):
    characters = ['@', '%', '&', '#', '=', '?', '+', '*', '$', '^', '|', '~', '`', '[', ']', '{', '}', '<', '>', '\'', '"', '\\']

    characters_found = []
    for character in characters:
        if character in url:
            characters_found.append(character)
    
    if characters_found:
        return {"encontrado": True, "caracteres": characters_found}
    else:
        return {"encontrado": False}

def whois_domain(domain):

    whois_out = subprocess.run(["whois", domain], capture_output=True, text=True).stdout

    for line in whois_out.splitlines():
        if "Creation Date" in line or "created:" in line.lower() or "Created On" in line:
            date_str = line.split(": ")[-1].strip()
            break
    else:
        return {"encontrado": False}

    for model in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
        try:
            creation_date = datetime.strptime(date_str, model)
            break
        except ValueError:
            continue
    else:
        return ("Erro para extrair data")

    domain_age = datetime.now().year - creation_date.year
    return {"encontrado": True, "idade": domain_age}

def openssl_certificate(domain, porta=443):
    try:
        cmd_sclient = [
            "openssl", "s_client",
            "-connect", f"{domain}:{porta}",
            "-servername", domain,
            "-showcerts"
        ]
        response = subprocess.run(cmd_sclient, capture_output=True, text=True, input='', timeout=10)

        cert_raw = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            response.stdout, re.DOTALL
        )

        if not cert_raw:
            return {"encontrado": False}

        cert_pem = cert_raw.group(0)

        cmd_x509 = ["openssl", "x509", "-noout", "-issuer", "-dates", "-subject", "-ext", "subjectAltName"]
        proc = subprocess.run(cmd_x509, input=cert_pem, capture_output=True, text=True)

        if proc.returncode != 0:
            print(proc.stderr)
            return "Erro para pegar informações"

        output = proc.stdout

        sender = re.search(r'issuer=.*?O\s*=\s*([^,\n]+)', output)
        sender = sender.group(1).strip() if sender else 'Desconhecido'

        valid_from = re.search(r'notBefore=(.*)', output)

        expiration = re.search(r'notAfter=(.*)', output)
        expiration = datetime.strptime(expiration.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                                       
        sans = re.findall(r'DNS:([^\s,]+)', output)

        if domain in sans or any(san.startswith("*.") and domain.endswith(san[1:]) for san in sans):
            match_domain = True
        else:
            match_domain = False

        return {"encontrado": True, "emissor": sender, "expiration": f"{expiration.day:02d}/{expiration.month:02d}/{expiration.year}", "corresponde": match_domain}

    except subprocess.TimeoutExpired:
        return "Erro timeout ao tentar conectar com OpenSSL"
    except Exception as e:
        return f"Erro ao analisar certificado: {e}"

def levenshtein_distance(domain):
    safe_domains = [
        "google.com",
        "facebook.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com"
    ]

    suspicious_matches = {}
    for safe_domain in safe_domains:
        distancia = Levenshtein.distance(domain, safe_domain)
        if distancia <= 2 and distancia != 0:
            suspicious_matches[safe_domain] = distancia

    if suspicious_matches:
        return {"encontrado": True, "correspondencias": suspicious_matches}

def sensitive_information(url):
    sensitive_input = ['password', 'pass', 'senha', 'username', 'login', 'email', 'username', 'cpf', 'ssn', 'credit', 'card', 'cvv']

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        # Verifica se há formulários
        forms = soup.find_all('form')
        sensitive_found = []

        for form in forms:
            inputs = form.find_all('input')
            for input in inputs:
                name = (input.get('name') or '').lower()
                type = (input.get('type') or '').lower()
                if any(word in name for word in sensitive_input) or type == 'password':
                    sensitive_found.append((name, type))

        if sensitive_found:
            return {"encontrado": True, "informacoes": sensitive_found}
        else:
            return {"encontrado": False}

    except Exception as e:
        return f"Erro ao analisar conteúdo HTML: {e}"

def suspicious_redirect(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        history = response.history
        redirects = [r.url for r in history]
        destiny = response.url

        domain_origin = url.split("//")[-1].split("/")[0].lower()
        domain_destiny = destiny.split("//")[-1].split("/")[0].lower()

        return {"encontrado": len(history) > 0, "destino_final": domain_destiny, "suspeito": domain_origin != domain_destiny}

    except requests.exceptions.RequestException as e:
        return "Erro ao realizar GET"