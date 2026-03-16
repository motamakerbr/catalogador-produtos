from flask import Flask, render_template, request, jsonify, redirect, session, url_for
import sqlite3
import os
import requests
import secrets
import hashlib
import base64
import cloudinary
import cloudinary.uploader

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave-secreta-local')

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET')
)

ML_APP_ID = os.environ.get('ML_APP_ID')
ML_SECRET_KEY = os.environ.get('ML_SECRET_KEY')
ML_REDIRECT_URI = os.environ.get('ML_REDIRECT_URI')

def init_db():
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS catalogos
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nome TEXT NOT NULL,
                  descricao TEXT,
                  cor TEXT DEFAULT '#667eea',
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS produtos
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nome TEXT NOT NULL,
                  descricao TEXT,
                  preco REAL,
                  estoque INTEGER,
                  categoria TEXT,
                  catalogo_id INTEGER,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (catalogo_id) REFERENCES catalogos(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS fotos
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  produto_id INTEGER,
                  url TEXT,
                  public_id TEXT,
                  principal INTEGER DEFAULT 0,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (produto_id) REFERENCES produtos(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  plataforma TEXT,
                  access_token TEXT,
                  refresh_token TEXT,
                  user_id TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pkce_temp
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  code_verifier TEXT,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nome TEXT,
                  email TEXT UNIQUE,
                  senha TEXT,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('produtos.db')
    conn.row_factory = sqlite3.Row
    return conn

# ── AUTH ──
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        conn = get_db()
        user = conn.execute('SELECT * FROM usuarios WHERE email=?', (data['email'],)).fetchone()
        conn.close()
        if user and user['senha'] == hashlib.sha256(data['senha'].encode()).hexdigest():
            session['user_id'] = user['id']
            session['user_nome'] = user['nome']
            return jsonify({'success': True})
        return jsonify({'success': False, 'erro': 'Email ou senha incorretos'})
    return render_template('login.html')

@app.route('/registro', methods=['POST'])
def registro():
    data = request.json
    senha_hash = hashlib.sha256(data['senha'].encode()).hexdigest()
    try:
        conn = get_db()
        conn.execute('INSERT INTO usuarios (nome, email, senha) VALUES (?,?,?)',
                     (data['nome'], data['email'], senha_hash))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'erro': 'Email já cadastrado'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ── PÁGINAS ──
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    ml_conectado = conn.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'").fetchone() is not None
    catalogos = conn.execute('SELECT * FROM catalogos ORDER BY nome').fetchall()
    conn.close()
    return render_template('index.html', ml_conectado=ml_conectado, catalogos=catalogos, user_nome=session.get('user_nome'))

# ── CATÁLOGOS ──
@app.route('/catalogos', methods=['GET'])
def listar_catalogos():
    conn = get_db()
    catalogos = conn.execute('SELECT * FROM catalogos ORDER BY nome').fetchall()
    conn.close()
    return jsonify([dict(c) for c in catalogos])

@app.route('/catalogos', methods=['POST'])
def criar_catalogo():
    data = request.json
    conn = get_db()
    conn.execute('INSERT INTO catalogos (nome, descricao, cor) VALUES (?,?,?)',
                 (data['nome'], data.get('descricao',''), data.get('cor','#667eea')))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/catalogos/<int:id>', methods=['DELETE'])
def deletar_catalogo(id):
    conn = get_db()
    conn.execute('DELETE FROM catalogos WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── PRODUTOS ──
@app.route('/produtos', methods=['GET'])
def listar_produtos():
    catalogo_id = request.args.get('catalogo_id')
    conn = get_db()
    if catalogo_id:
        produtos = conn.execute('''SELECT p.*, c.nome as catalogo_nome, c.cor as catalogo_cor,
                                   f.url as foto_principal
                                   FROM produtos p
                                   LEFT JOIN catalogos c ON c.id = p.catalogo_id
                                   LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                                   WHERE p.catalogo_id = ?
                                   ORDER BY p.criado_em DESC''', (catalogo_id,)).fetchall()
    else:
        produtos = conn.execute('''SELECT p.*, c.nome as catalogo_nome, c.cor as catalogo_cor,
                                   f.url as foto_principal
                                   FROM produtos p
                                   LEFT JOIN catalogos c ON c.id = p.catalogo_id
                                   LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                                   ORDER BY p.criado_em DESC''').fetchall()
    conn.close()
    return jsonify([dict(p) for p in produtos])

@app.route('/produtos', methods=['POST'])
def cadastrar_produto():
    data = request.json
    conn = get_db()
    cursor = conn.execute('''INSERT INTO produtos (nome, descricao, preco, estoque, categoria, catalogo_id)
                             VALUES (?,?,?,?,?,?)''',
                          (data['nome'], data['descricao'], data['preco'],
                           data['estoque'], data['categoria'], data.get('catalogo_id')))
    produto_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'id': produto_id})

@app.route('/produtos/<int:id>', methods=['DELETE'])
def deletar_produto(id):
    conn = get_db()
    conn.execute('DELETE FROM fotos WHERE produto_id=?', (id,))
    conn.execute('DELETE FROM produtos WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── FOTOS ──
@app.route('/fotos/upload', methods=['POST'])
def upload_foto():
    if 'foto' not in request.files:
        return jsonify({'success': False, 'erro': 'Nenhuma foto enviada'})
    file = request.files['foto']
    resultado = cloudinary.uploader.upload(file, folder='catalogador')
    return jsonify({
        'success': True,
        'url': resultado['secure_url'],
        'public_id': resultado['public_id']
    })

@app.route('/fotos', methods=['POST'])
def salvar_foto():
    data = request.json
    conn = get_db()
    if data.get('principal'):
        conn.execute('UPDATE fotos SET principal=0 WHERE produto_id=?', (data['produto_id'],))
    conn.execute('INSERT INTO fotos (produto_id, url, public_id, principal) VALUES (?,?,?,?)',
                 (data['produto_id'], data['url'], data['public_id'], 1 if data.get('principal') else 0))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/fotos/<int:produto_id>', methods=['GET'])
def listar_fotos(produto_id):
    conn = get_db()
    fotos = conn.execute('SELECT * FROM fotos WHERE produto_id=? ORDER BY principal DESC', (produto_id,)).fetchall()
    conn.close()
    return jsonify([dict(f) for f in fotos])

@app.route('/fotos/<int:id>', methods=['DELETE'])
def deletar_foto(id):
    conn = get_db()
    foto = conn.execute('SELECT * FROM fotos WHERE id=?', (id,)).fetchone()
    if foto:
        try:
            cloudinary.uploader.destroy(foto['public_id'])
        except:
            pass
        conn.execute('DELETE FROM fotos WHERE id=?', (id,))
        conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── MERCADO LIVRE ──
@app.route('/conectar/mercadolivre')
def conectar_mercadolivre():
    code_verifier = secrets.token_urlsafe(64)
    conn = get_db()
    conn.execute("DELETE FROM pkce_temp")
    conn.execute("INSERT INTO pkce_temp (code_verifier) VALUES (?)", (code_verifier,))
    conn.commit()
    conn.close()
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()
    url = (f"https://auth.mercadolivre.com.br/authorization"
           f"?response_type=code&client_id={ML_APP_ID}"
           f"&redirect_uri={ML_REDIRECT_URI}"
           f"&code_challenge={code_challenge}"
           f"&code_challenge_method=S256")
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Erro na autenticação", 400
    conn = get_db()
    row = conn.execute("SELECT code_verifier FROM pkce_temp ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return "Erro: code_verifier não encontrado", 400
    code_verifier = row['code_verifier']
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
        conn.execute("DELETE FROM tokens WHERE plataforma='mercadolivre'")
        conn.execute("INSERT INTO tokens (plataforma, access_token, refresh_token, user_id) VALUES (?,?,?,?)",
                     ('mercadolivre', dados['access_token'], dados['refresh_token'], str(dados['user_id'])))
        conn.commit()
        conn.close()
        return redirect('/')
    else:
        return f"Erro ao obter token: {resposta.json()}", 400

# ── DASHBOARD ──
@app.route('/dashboard')
def dashboard():
    conn = get_db()
    total_produtos = conn.execute('SELECT COUNT(*) as t FROM produtos').fetchone()['t']
    total_catalogos = conn.execute('SELECT COUNT(*) as t FROM catalogos').fetchone()['t']
    total_fotos = conn.execute('SELECT COUNT(*) as t FROM fotos').fetchone()['t']
    ml_conectado = conn.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'").fetchone() is not None
    por_catalogo = conn.execute('''SELECT c.nome, c.cor, COUNT(p.id) as total
                                   FROM catalogos c
                                   LEFT JOIN produtos p ON p.catalogo_id = c.id
                                   GROUP BY c.id ORDER BY total DESC''').fetchall()
    conn.close()
    return jsonify({
        'total_produtos': total_produtos,
        'total_catalogos': total_catalogos,
        'total_fotos': total_fotos,
        'ml_conectado': ml_conectado,
        'por_catalogo': [dict(p) for p in por_catalogo]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
