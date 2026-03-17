from flask import Flask, render_template, request, jsonify, redirect, session
import os
import json
import requests
import secrets
import hashlib
import base64
import cloudinary
import cloudinary.uploader
from datetime import datetime
import pg8000.dbapi as pg

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
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

def get_db():
    conn = pg.connect(
        host=os.environ.get('DB_HOST'),
        port=int(os.environ.get('DB_PORT', 5432)),
        database=os.environ.get('DB_NAME'),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASS')
    )
    return conn

def fetchone(cursor):
    row = cursor.fetchone()
    if row is None:
        return None
    cols = [desc[0] for desc in cursor.description]
    return dict(zip(cols, row))

def fetchall(cursor):
    rows = cursor.fetchall()
    cols = [desc[0] for desc in cursor.description]
    return [dict(zip(cols, row)) for row in rows]

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS catalogos
                 (id SERIAL PRIMARY KEY,
                  nome TEXT NOT NULL,
                  descricao TEXT,
                  cor TEXT DEFAULT '#667eea',
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS produtos
                 (id SERIAL PRIMARY KEY,
                  nome TEXT NOT NULL,
                  descricao TEXT,
                  preco REAL,
                  estoque INTEGER,
                  categoria TEXT,
                  catalogo_id INTEGER,
                  usuario_id INTEGER,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS fotos
                 (id SERIAL PRIMARY KEY,
                  produto_id INTEGER,
                  url TEXT,
                  public_id TEXT,
                  principal INTEGER DEFAULT 0,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens
                 (id SERIAL PRIMARY KEY,
                  plataforma TEXT,
                  access_token TEXT,
                  refresh_token TEXT,
                  user_id TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pkce_temp
                 (id SERIAL PRIMARY KEY,
                  code_verifier TEXT,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id SERIAL PRIMARY KEY,
                  nome TEXT,
                  email TEXT UNIQUE,
                  senha TEXT,
                  nivel TEXT DEFAULT 'usuario',
                  ativo INTEGER DEFAULT 1,
                  ultimo_acesso TIMESTAMP,
                  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def is_admin():
    if 'user_id' not in session:
        return False
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT nivel FROM usuarios WHERE id=%s', (session['user_id'],))
    user = fetchone(c)
    conn.close()
    return user and user['nivel'] == 'admin'

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            return jsonify({'success': False, 'erro': 'Acesso negado'}), 403
        return f(*args, **kwargs)
    return decorated

def chamar_ia(prompt):
    resposta = requests.post(
        'https://api.groq.com/openai/v1/chat/completions',
        headers={'Authorization': f'Bearer {GROQ_API_KEY}'},
        json={
            'model': 'llama-3.3-70b-versatile',
            'messages': [
                {
                    'role': 'system',
                    'content': '''Você é um copywriter especialista em e-commerce brasileiro com 10 anos de experiência vendendo em Mercado Livre, Shopee, Amazon e Magalu.
Você conhece profundamente o comportamento do consumidor brasileiro, técnicas de SEO para marketplaces e psicologia de vendas.
Você SEMPRE cria títulos e descrições ORIGINAIS e CRIATIVAS, nunca copia o que o usuário escreveu.
Você usa gatilhos mentais, destaca benefícios reais e usa linguagem persuasiva.
Você SEMPRE responde em JSON válido, sem texto adicional.'''
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'temperature': 0.9,
            'max_tokens': 2000
        }
    )
    dados = resposta.json()
    if 'choices' not in dados:
        raise Exception(str(dados))
    texto = dados['choices'][0]['message']['content']
    texto = texto.replace('```json', '').replace('```', '').strip()
    # Remove caracteres de controle inválidos
    import re
    texto = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', texto)
    return json.loads(texto)

# ── AUTH ──
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM usuarios WHERE email=%s', (data['email'],))
        user = fetchone(c)
        if user and user['senha'] == hashlib.sha256(data['senha'].encode()).hexdigest():
            if not user['ativo']:
                conn.close()
                return jsonify({'success': False, 'erro': 'Usuário bloqueado'})
            c.execute('UPDATE usuarios SET ultimo_acesso=%s WHERE id=%s',
                      (datetime.now(), user['id']))
            conn.commit()
            conn.close()
            session['user_id'] = user['id']
            session['user_nome'] = user['nome']
            session['user_nivel'] = user['nivel']
            return jsonify({'success': True})
        conn.close()
        return jsonify({'success': False, 'erro': 'Email ou senha incorretos'})
    return render_template('login.html')

@app.route('/registro', methods=['POST'])
def registro():
    data = request.json
    senha_hash = hashlib.sha256(data['senha'].encode()).hexdigest()
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) as t FROM usuarios')
        total = fetchone(c)['t']
        nivel = 'admin' if total == 0 else 'usuario'
        c.execute('INSERT INTO usuarios (nome, email, senha, nivel) VALUES (%s,%s,%s,%s)',
                  (data['nome'], data['email'], senha_hash, nivel))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'nivel': nivel})
    except Exception as e:
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
    c = conn.cursor()
    c.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'")
    ml_conectado = fetchone(c) is not None
    c.execute('SELECT * FROM catalogos ORDER BY nome')
    catalogos = fetchall(c)
    conn.close()
    return render_template('index.html',
                           ml_conectado=ml_conectado,
                           catalogos=catalogos,
                           user_nome=session.get('user_nome'),
                           user_nivel=session.get('user_nivel'))

# ── GESTÃO DE USUÁRIOS ──
@app.route('/admin/usuarios')
def admin_usuarios():
    if not is_admin():
        return redirect('/')
    return render_template('admin_usuarios.html',
                           user_nome=session.get('user_nome'),
                           user_nivel=session.get('user_nivel'))

@app.route('/api/usuarios', methods=['GET'])
@admin_required
def listar_usuarios():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, nome, email, nivel, ativo, ultimo_acesso, criado_em FROM usuarios ORDER BY criado_em DESC')
    usuarios = fetchall(c)
    conn.close()
    return jsonify(usuarios)

@app.route('/api/usuarios', methods=['POST'])
@admin_required
def criar_usuario():
    data = request.json
    senha_hash = hashlib.sha256(data['senha'].encode()).hexdigest()
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO usuarios (nome, email, senha, nivel) VALUES (%s,%s,%s,%s)',
                  (data['nome'], data['email'], senha_hash, data.get('nivel', 'usuario')))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'erro': 'Email já cadastrado'})

@app.route('/api/usuarios/<int:id>', methods=['PUT'])
@admin_required
def atualizar_usuario(id):
    data = request.json
    conn = get_db()
    c = conn.cursor()
    if 'nivel' in data:
        c.execute('UPDATE usuarios SET nivel=%s WHERE id=%s', (data['nivel'], id))
    if 'ativo' in data:
        c.execute('UPDATE usuarios SET ativo=%s WHERE id=%s', (data['ativo'], id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/usuarios/<int:id>', methods=['DELETE'])
@admin_required
def deletar_usuario(id):
    if id == session.get('user_id'):
        return jsonify({'success': False, 'erro': 'Não é possível deletar seu próprio usuário'})
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM usuarios WHERE id=%s', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── CATÁLOGOS ──
@app.route('/catalogos', methods=['GET'])
def listar_catalogos():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM catalogos ORDER BY nome')
    catalogos = fetchall(c)
    conn.close()
    return jsonify(catalogos)

@app.route('/catalogos', methods=['POST'])
def criar_catalogo():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO catalogos (nome, descricao, cor) VALUES (%s,%s,%s)',
              (data['nome'], data.get('descricao',''), data.get('cor','#667eea')))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/catalogos/<int:id>', methods=['DELETE'])
def deletar_catalogo(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM catalogos WHERE id=%s', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── PRODUTOS ──
@app.route('/produtos', methods=['GET'])
def listar_produtos():
    catalogo_id = request.args.get('catalogo_id')
    conn = get_db()
    c = conn.cursor()
    usuario_id = session.get('user_id')
    nivel = session.get('user_nivel')
    if catalogo_id:
        if nivel == 'admin':
            c.execute('''SELECT p.*, cat.nome as catalogo_nome, cat.cor as catalogo_cor,
                         f.url as foto_principal
                         FROM produtos p
                         LEFT JOIN catalogos cat ON cat.id = p.catalogo_id
                         LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                         WHERE p.catalogo_id = %s
                         ORDER BY p.criado_em DESC''', (catalogo_id,))
        else:
            c.execute('''SELECT p.*, cat.nome as catalogo_nome, cat.cor as catalogo_cor,
                         f.url as foto_principal
                         FROM produtos p
                         LEFT JOIN catalogos cat ON cat.id = p.catalogo_id
                         LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                         WHERE p.catalogo_id = %s AND p.usuario_id = %s
                         ORDER BY p.criado_em DESC''', (catalogo_id, usuario_id))
    else:
        if nivel == 'admin':
            c.execute('''SELECT p.*, cat.nome as catalogo_nome, cat.cor as catalogo_cor,
                         f.url as foto_principal
                         FROM produtos p
                         LEFT JOIN catalogos cat ON cat.id = p.catalogo_id
                         LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                         ORDER BY p.criado_em DESC''')
        else:
            c.execute('''SELECT p.*, cat.nome as catalogo_nome, cat.cor as catalogo_cor,
                         f.url as foto_principal
                         FROM produtos p
                         LEFT JOIN catalogos cat ON cat.id = p.catalogo_id
                         LEFT JOIN fotos f ON f.produto_id = p.id AND f.principal = 1
                         WHERE p.usuario_id = %s
                         ORDER BY p.criado_em DESC''', (usuario_id,))
    produtos = fetchall(c)
    conn.close()
    return jsonify(produtos)

@app.route('/produtos', methods=['POST'])
def cadastrar_produto():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO produtos (nome, descricao, preco, estoque, categoria, catalogo_id, usuario_id)
                 VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
              (data['nome'], data['descricao'], data['preco'],
               data['estoque'], data['categoria'],
               data.get('catalogo_id'), session.get('user_id')))
    produto_id = fetchone(c)['id']
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'id': produto_id})

@app.route('/produtos/<int:id>', methods=['DELETE'])
def deletar_produto(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM fotos WHERE produto_id=%s', (id,))
    c.execute('DELETE FROM produtos WHERE id=%s', (id,))
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
    c = conn.cursor()
    if data.get('principal'):
        c.execute('UPDATE fotos SET principal=0 WHERE produto_id=%s', (data['produto_id'],))
    c.execute('INSERT INTO fotos (produto_id, url, public_id, principal) VALUES (%s,%s,%s,%s)',
              (data['produto_id'], data['url'], data['public_id'], 1 if data.get('principal') else 0))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/fotos/<int:produto_id>', methods=['GET'])
def listar_fotos(produto_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM fotos WHERE produto_id=%s ORDER BY principal DESC', (produto_id,))
    fotos = fetchall(c)
    conn.close()
    return jsonify(fotos)

@app.route('/fotos/<int:id>', methods=['DELETE'])
def deletar_foto(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM fotos WHERE id=%s', (id,))
    foto = fetchone(c)
    if foto:
        try:
            cloudinary.uploader.destroy(foto['public_id'])
        except:
            pass
        c.execute('DELETE FROM fotos WHERE id=%s', (id,))
        conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── MERCADO LIVRE ──
@app.route('/conectar/mercadolivre')
def conectar_mercadolivre():
    code_verifier = secrets.token_urlsafe(64)
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM pkce_temp")
    c.execute("INSERT INTO pkce_temp (code_verifier) VALUES (%s)", (code_verifier,))
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
    c = conn.cursor()
    c.execute("SELECT code_verifier FROM pkce_temp ORDER BY id DESC LIMIT 1")
    row = fetchone(c)
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
        c.execute("DELETE FROM tokens WHERE plataforma='mercadolivre'")
        c.execute("INSERT INTO tokens (plataforma, access_token, refresh_token, user_id) VALUES (%s,%s,%s,%s)",
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
    c = conn.cursor()
    usuario_id = session.get('user_id')
    nivel = session.get('user_nivel')
    if nivel == 'admin':
        c.execute('SELECT COUNT(*) as t FROM produtos')
        total_produtos = fetchone(c)['t']
        c.execute('SELECT COUNT(*) as t FROM usuarios')
        total_usuarios = fetchone(c)['t']
    else:
        c.execute('SELECT COUNT(*) as t FROM produtos WHERE usuario_id=%s', (usuario_id,))
        total_produtos = fetchone(c)['t']
        total_usuarios = None
    c.execute('SELECT COUNT(*) as t FROM catalogos')
    total_catalogos = fetchone(c)['t']
    c.execute('SELECT COUNT(*) as t FROM fotos')
    total_fotos = fetchone(c)['t']
    c.execute("SELECT access_token FROM tokens WHERE plataforma='mercadolivre'")
    ml_conectado = fetchone(c) is not None
    c.execute('''SELECT cat.nome, cat.cor, COUNT(p.id) as total
                 FROM catalogos cat
                 LEFT JOIN produtos p ON p.catalogo_id = cat.id
                 GROUP BY cat.id, cat.nome, cat.cor
                 ORDER BY total DESC''')
    por_catalogo = fetchall(c)
    conn.close()
    return jsonify({
        'total_produtos': total_produtos,
        'total_catalogos': total_catalogos,
        'total_fotos': total_fotos,
        'total_usuarios': total_usuarios,
        'ml_conectado': ml_conectado,
        'por_catalogo': por_catalogo
    })

# ── IA ──
@app.route('/ia/gerar-anuncio', methods=['POST'])
def gerar_anuncio():
    data = request.json
    nome = data.get('nome', '')
    descricao = data.get('descricao', '')
    categoria = data.get('categoria', '')
    preco = data.get('preco', '')
    marketplace = data.get('marketplace', 'geral')

    regras = {
        'mercadolivre': 'Mercado Livre Brasil. Título máximo 60 caracteres. Descrição detalhada com bullet points. Destaque frete grátis e garantia.',
        'shopee': 'Shopee Brasil. Título máximo 120 caracteres. Use emojis. Descrição com hashtags no final.',
        'amazon': 'Amazon Brasil. Título máximo 200 caracteres. Descrição técnica e detalhada. Bullet points com benefícios.',
        'magalu': 'Magazine Luiza. Título máximo 100 caracteres. Descrição focada em benefícios para o consumidor.'
    }

    prompt = f"""Crie um anúncio ORIGINAL e PERSUASIVO para {marketplace.upper()} para o seguinte produto:

Nome do produto: {nome}
Informações base: {descricao}
Categoria: {categoria}
Preço: R$ {preco}

Regras específicas para {marketplace}: {regras.get(marketplace, 'Marketplace brasileiro.')}

IMPORTANTE:
- NÃO copie a descrição fornecida, crie algo ORIGINAL e CRIATIVO
- Use gatilhos mentais como escassez, prova social, benefícios
- Pense como um vendedor top do marketplace
- Sugira um preço competitivo baseado no mercado brasileiro atual
- As palavras-chave devem ser termos que compradores reais pesquisam

Responda APENAS em JSON válido:
{{
  "titulo": "título otimizado e atrativo",
  "descricao": "descrição completa, persuasiva e original com pelo menos 3 parágrafos",
  "bullet_points": ["benefício 1", "benefício 2", "benefício 3", "benefício 4", "benefício 5"],
  "palavras_chave": ["termo1", "termo2", "termo3", "termo4", "termo5"],
  "preco_sugerido": 0.00,
  "dicas": "dica específica para aumentar as vendas deste produto"
}}"""

    try:
        resultado = chamar_ia(prompt)
        return jsonify({'success': True, 'resultado': resultado})
    except Exception as e:
        return jsonify({'success': False, 'erro': str(e)})

@app.route('/ia/sugerir-preco', methods=['POST'])
def sugerir_preco():
    data = request.json
    nome = data.get('nome', '')
    categoria = data.get('categoria', '')
    descricao = data.get('descricao', '')

    prompt = f"""Analise o produto abaixo e sugira uma faixa de preço competitiva para o mercado brasileiro:

Nome: {nome}
Categoria: {categoria}
Descrição: {descricao}

Considere:
- Preços praticados em Mercado Livre, Shopee e Amazon Brasil
- Margem de lucro saudável para o vendedor
- Competitividade no mercado
- Custos de frete e taxas dos marketplaces

Responda APENAS em JSON válido:
{{
  "preco_minimo": 0.00,
  "preco_sugerido": 0.00,
  "preco_maximo": 0.00,
  "justificativa": "explicação detalhada da precificação",
  "dicas_precificacao": ["dica1", "dica2", "dica3"]
}}"""

    try:
        resultado = chamar_ia(prompt)
        return jsonify({'success': True, 'resultado': resultado})
    except Exception as e:
        return jsonify({'success': False, 'erro': str(e)})
async function gerarImagem() {
        const nome = document.getElementById('img-nome').value;
        if (!nome) return alert('Preencha o nome do produto!');

        document.getElementById('loading-imagem').classList.add('visivel');
        document.getElementById('resultado-imagem').style.display = 'none';

        const res = await fetch('/ia/gerar-imagem', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                nome,
                categoria: document.getElementById('img-categoria').value,
                estilo: document.getElementById('img-estilo').value
            })
        });
        const data = await res.json();
        document.getElementById('loading-imagem').classList.remove('visivel');

        if (!data.success) return alert('Erro: ' + data.erro);

        document.getElementById('img-resultado').src = data.imagem;
        document.getElementById('resultado-imagem').style.display = 'block';
    }

    function baixarImagem() {
        const img = document.getElementById('img-resultado').src;
        const a = document.createElement('a');
        a.href = img;
        a.download = 'produto-ia.jpg';
        a.click();
    }
```

Salva tudo com **Cmd + S** e no terminal:
```
git add .
git commit -m "adiciona gerador de imagens"
git push
@app.route('/ia')
def ia():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('ia.html',
                           user_nome=session.get('user_nome'),
                           user_nivel=session.get('user_nivel'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
