from flask import Flask, render_template, request, jsonify, redirect, session
import sqlite3
import os
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave-secreta-local')

ML_APP_ID = os.environ.get('ML_APP_ID')
ML_SECRET_KEY = os.environ.get('ML_SECRET_KEY')
ML_REDIRECT_URI = os.environ.get('ML_REDIRECT_URI')

def init_db():
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS produtos
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nome TEXT NOT NULL,
                  descricao TEXT,
                  preco REAL,
                  estoque INTEGER,
                  categoria TEXT,
                  imagem_url TEXT,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  plataforma TEXT,
                  access_token TEXT,
                  refresh_token TEXT,
                  user_id TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'")
    ml_conectado = c.fetchone() is not None
    conn.close()
    return render_template('index.html', ml_conectado=ml_conectado)

@app.route('/produtos', methods=['GET'])
def listar_produtos():
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('SELECT * FROM produtos ORDER BY criado_em DESC')
    produtos = c.fetchall()
    conn.close()
    return jsonify(produtos)

@app.route('/produtos', methods=['POST'])
def cadastrar_produto():
    data = request.json
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('''INSERT INTO produtos (nome, descricao, preco, estoque, categoria, imagem_url)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (data['nome'], data['descricao'], data['preco'],
               data['estoque'], data['categoria'], data['imagem_url']))
    conn.commit()
    produto_id = c.lastrowid
    conn.close()

    resultados = {}
    if data.get('marketplaces') and 'mercadolivre' in data['marketplaces']:
        resultados['mercadolivre'] = publicar_mercadolivre(produto_id, data)

    return jsonify({'success': True, 'id': produto_id, 'resultados': resultados})

def publicar_mercadolivre(produto_id, data):
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'")
    token = c.fetchone()
    conn.close()

    if not token:
        return {'success': False, 'erro': 'Mercado Livre não conectado'}

    categorias_ml = {
        'eletronicos': 'MLB1648',
        'roupas': 'MLB1430',
        'casa': 'MLB1574',
        'esportes': 'MLB1276',
        'beleza': 'MLB1246',
        'outros': 'MLB3530'
    }

    payload = {
        "title": data['nome'],
        "category_id": categorias_ml.get(data['categoria'], 'MLB3530'),
        "price": data['preco'],
        "currency_id": "BRL",
        "available_quantity": data['estoque'],
        "buying_mode": "buy_it_now",
        "condition": "new",
        "listing_type_id": "gold_special",
        "description": {"plain_text": data['descricao']},
        "pictures": [{"source": data['imagem_url']}] if data.get('imagem_url') else []
    }

    resposta = requests.post(
        'https://api.mercadolibre.com/items',
        json=payload,
        headers={'Authorization': f"Bearer {token[0]}"}
    )

    if resposta.status_code == 201:
        return {'success': True, 'item_id': resposta.json().get('id')}
    else:
        return {'success': False, 'erro': resposta.json()}

import secrets
import hashlib
import base64

@app.route('/conectar/mercadolivre')
def conectar_mercadolivre():
    code_verifier = secrets.token_urlsafe(64)
    session['code_verifier'] = code_verifier
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()
    url = (f"https://auth.mercadolivre.com.br/authorization"
           f"?response_type=code"
           f"&client_id={ML_APP_ID}"
           f"&redirect_uri={ML_REDIRECT_URI}"
           f"&code_challenge={code_challenge}"
           f"&code_challenge_method=S256")
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Erro na autenticação", 400

    code_verifier = session.get('code_verifier')

    resposta = requests.post('https://api.mercadolibre.com/oauth/token', data={
        'grant_type': 'authorization_code',
        'client_id': ML_APP_ID,
        'client_secret': ML_SECRET_KEY,
        'code': code,
        'redirect_uri': ML_REDIRECT_URI,
        'code_verifier': code_verifier
    })

    if resposta.status_code == 200:
        dados = resposta.json()
        conn = sqlite3.connect('produtos.db')
        c = conn.cursor()
        c.execute("DELETE FROM tokens WHERE plataforma='mercadolivre'")
        c.execute("INSERT INTO tokens (plataforma, access_token, refresh_token, user_id) VALUES (?, ?, ?, ?)",
                  ('mercadolivre', dados['access_token'], dados['refresh_token'], str(dados['user_id'])))
        conn.commit()
        conn.close()
        return redirect('/')
    else:
        return f"Erro ao obter token: {resposta.json()}", 400

@app.route('/produtos/<int:id>', methods=['DELETE'])
def deletar_produto(id):
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('DELETE FROM produtos WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)