# Phishing Detection

Ferramenta para examinar URLs e detectar phishing

Vídeo demonstrando o funcionamento da ferramenta disponível [aqui]( https://youtu.be/YXB-q7FbDE4).

Foram analisadas as seguintes características da URL:
- Presença em listas de phishing (safeBrowsing)
- Presença de números substituindo letras
- Presença de caracteres especiais
- Consulta de idade do domínio (WHOIS)
- Análise de certificado SSL
- Detecção de redirecionamentos suspeitos
- Verificação de similaridade com outros domínios (Levenshtein)
- Solicitação de informações sensíveis em formulários

Para executar a ferramenta é necessário:

Instalar as dependências, pode ser feito com o comando abaixo:

`pip install -r requirements.txt`

Rodar a API, para isso execute o comando abaixo dentro do diretório **backend** (onde se encontra o arquivo **app.py**).

`fastapi dev app.py`

Para abrir a página web, foi utilizada a extensão Live Server (ela pode ser instalada no VSCode). Para abrir com O Live Server basta abrir o arquivo **index.html** que está dentro da pasta **templates**, clicar com o botão direito do mouse e selecionar:

 `Open with Live Server`

 Com isso, a aplicação estará rodando no navegador e será possível analisar URLs.
