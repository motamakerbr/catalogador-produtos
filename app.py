from flask import Flask, render_template, request, jsonify
import sqlite3
import os

app = Flask(__name__)

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
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

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
    return jsonify({'success': True, 'id': produto_id})

@app.route('/produtos/<int:id>', methods=['DELETE'])
def deletar_produto(id):
    conn = sqlite3.connect('produtos.db')
    c = conn.cursor()
    c.execute('DELETE FROM produtos WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)