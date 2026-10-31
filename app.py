from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "chave_super_secreta_devsecops_para_sessoes"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///plantas_seguro.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limite de 5MB por upload (Proteção DoS)

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Modelos de Base de Dados (Protegidos contra SQL Injection via ORM) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Flor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    curiosidade = db.Column(db.Text, nullable=False)
    imagem = db.Column(db.String(255), nullable=False)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Rotas de Autenticação & Aplicação ---
@app.route('/')
def index():
    flores = Flor.query.all()
    return render_template('index.html', flores=flores)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash("Preencha todos os campos!")
            return redirect(url_for('register'))
            
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Nome de utilizador já existe.")
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password)
        novo_usuario = User(username=username, password_hash=hashed_password)
        db.session.add(novo_usuario)
        db.session.commit()
        
        flash("Conta criada com sucesso! Podes fazer login.")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login efetuado com sucesso!")
            return redirect(url_for('index'))
        else:
            flash("Credenciais inválidas.")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão terminada.")
    return redirect(url_for('index'))

@app.route('/adicionar', methods=['POST'])
def adicionar_flor():
    # Validação de Controlo de Acesso (DevSecOps)
    if 'user_id' not in session:
        flash("Precisas de fazer login para cadastrar uma planta!")
        return redirect(url_for('login'))
        
    nome = request.form['nome']
    descricao = request.form['descricao']
    curiosidade = request.form['curiosidade']
    file = request.files.get('imagem')

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        nova_flor = Flor(nome=nome, descricao=descricao, curiosidade=curiosidade, imagem=filename)
        db.session.add(nova_flor)
        db.session.commit()
        flash("Planta adicionada com sucesso!")
    else:
        flash("Erro: Ficheiro inválido ou não suportado (Apenas PNG, JPG ou JPEG).")
        
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=False)