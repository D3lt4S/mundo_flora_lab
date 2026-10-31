from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "chave_super_secreta_devsecops_para_sessoes"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///plantas_seguro.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limite de 5MB por upload (Proteção DoS)

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Modelos de Base de Dados ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

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
            
        if User.query.filter_by(username=username).first():
            flash("Nome de utilizador já existe.")
            return redirect(url_for('register'))
            
        is_first_user = User.query.count() == 0
        
        hashed_password = generate_password_hash(password)
        novo_usuario = User(
            username=username, 
            password_hash=hashed_password, 
            is_admin=is_first_user
        )
        db.session.add(novo_usuario)
        db.session.commit()
        
        tipo_conta = "Administrador (Primeiro Registo)" if is_first_user else "Utilizador Comum"
        flash(f"Conta criada com sucesso! Tipo: {tipo_conta}")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash("Credenciais inválidas.")
            return redirect(url_for('login'))
            
        if user.locked_until and user.locked_until > datetime.utcnow():
            tempo_restante = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f"Conta temporariamente bloqueada. Tente novamente em {tempo_restante + 1} minutos.")
            return redirect(url_for('login'))
            
        if check_password_hash(user.password_hash, password):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            flash("Login efetuado com sucesso!")
            return redirect(url_for('index'))
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                db.session.commit()
                flash("Muitas tentativas falhadas. Conta bloqueada por 5 minutos por segurança contra Brute Force.")
            else:
                db.session.commit()
                flash(f"Credenciais inválidas. Tentativa {user.failed_attempts} de 5.")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão terminada.")
    return redirect(url_for('index'))

# --- CRUD Completo com Restrição de Administrador ---

@app.route('/adicionar', methods=['POST'])
def adicionar_flor():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Acesso negado: Apenas a conta administradora pode cadastrar novas plantas!")
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

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar_flor(id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Acesso negado: Apenas a conta administradora pode editar registos!")
        return redirect(url_for('login'))
        
    flor = Flor.query.get_or_404(id)
    
    if request.method == 'POST':
        flor.nome = request.form['nome']
        flor.descricao = request.form['descricao']
        flor.curiosidade = request.form['curiosidade']
        
        file = request.files.get('imagem')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flor.imagem = filename
            
        db.session.commit()
        flash("Planta atualizada com sucesso!")
        return redirect(url_for('index'))
        
    return render_template('editar.html', flor=flor)

@app.route('/excluir/<int:id>', methods=['POST', 'GET'])
def excluir_flor(id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Acesso negado: Apenas a conta administradora pode excluir registos!")
        return redirect(url_for('login'))
        
    flor = Flor.query.get_or_404(id)
    db.session.delete(flor)
    db.session.commit()
    flash("Planta excluída com sucesso!")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=False)