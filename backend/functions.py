import requests
import json

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
            threat_type = []
            for match in data["matches"]:
                threat_type.append(match['threatType'])
            return {"encontrada": True, "tipo": threat_type}
        else:
            return {"encontrada": False}
    else:
        raise Exception(f"Erro na requisição (status {response.status_code})")

def replace_letters(url):
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

    domain = url.split("//")[-1].split("/")[0]
    domain = domain.lower()

    for char, substitute in letter_map.items():
        if substitute in domain:
            return True
    return False

def special_characters(url):
    characters = ['@', '%', '&', '#', '=', '?', '+', '*', '$', '^', '|', '~', '`', '[', ']', '{', '}', '<', '>', '\'', '"', '\\']

    for character in characters:
        if character in url:
            return True
    return False

