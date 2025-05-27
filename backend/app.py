import os
from dotenv import load_dotenv
from functions import *

from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()
load_dotenv()
key = os.getenv("API_KEY")

# Permissões
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

@app.post("/verificar")
def analisar_url(url: str = Form(...)):
    domain = url.split("//")[-1].split("/")[0].lower()

    return {
        "safe_browsing": safebrowsing_result(url, key),
        "leetspeak": replace_letters(domain),
        "caracteres_especiais": special_characters(url),
        "levenshtein": levenshtein_distance(domain),
        "informacoes_sensiveis": sensitive_information(url),
        "redirecionamento_suspeito": suspicious_redirect(url),
        "whois": whois_domain(domain),
        "certificado_ssl": openssl_certificate(domain)
    }