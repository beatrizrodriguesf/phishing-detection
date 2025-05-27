import requests
import json
from datetime import datetime
import Levenshtein
import whois
import ssl
from bs4 import BeautifulSoup
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
        return {"erro": "Erro na requisição"}

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
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"encontrado": False}

        domain_age = datetime.now().year - creation_date.year
        return {"encontrado": True, "idade": domain_age}

    except Exception as e:
        return {"erro": f"Erro ao consultar domínio: {e}"}

def openssl_certificate(domain, porta=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, porta), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        sender = issuer[0].value if issuer else "Desconhecido"

        expiration = cert.not_valid_after_utc
        valid_from = cert.not_valid_before_utc

        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        match_domain = domain in sans or any(san.startswith("*.") and domain.endswith(san[1:]) for san in sans)

        return {
            "encontrado": True,
            "emissor": sender,
            "expiration": expiration.strftime("%d/%m/%Y"),
            "corresponde": match_domain
        }

    except ssl.SSLError as e:
        return {"erro": f"Erro SSL: {e}"}
    except socket.timeout:
        return {"erro": "Timeout ao tentar conectar com o servidor"}
    except Exception as e:
        return {"erro": f"Erro ao analisar certificado: {e}"}

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
    else:
        return {"encontrado": False}

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
        return {"erro": f"Erro ao analisar conteúdo HTML: {e}"}

def suspicious_redirect(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        history = response.history
        redirects = [r.url for r in history]
        destiny = response.url

        domain_origin = url.split("//")[-1].split("/")[0].lower()
        domain_destiny = destiny.split("//")[-1].split("/")[0].lower()

        if len(history) > 0 or domain_origin == domain_destiny:
            return {"encontrado": False}
        else:
            return {"encontrado": True, "quantidade": len(history) > 0, "destino_final": domain_destiny}

    except requests.exceptions.RequestException as e:
        return {"erro": "Não foi possível realizar GET"}