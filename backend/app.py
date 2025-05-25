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
async def verificar_url(url: str = Form(...)):
    sb_resultado = safebrowsing_result(url, key)
    sub_numeros = replace_letters(url)
    especiais = special_characters(url)

    perigo = sb_resultado.get("encontrada", False) or sub_numeros or especiais

    resultado = {
        "url": url,
        "cor": "red" if perigo else "green",
        "safebrowsing": sb_resultado,
        "substituicao_numeros": sub_numeros,
        "caracteres_especiais": especiais
    }
    return JSONResponse(content=resultado)