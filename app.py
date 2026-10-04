from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
# Configurações de Segurança e Banco de Dados
app.secret_key = "chave_super_secreta_para_flash_messages"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///plantas.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
# Trava de segurança extra: Limita o upload a 5MB para evitar DoS
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 

db = SQLAlchemy(app)

# Validação estrita de extensão de arquivo
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Modelo do Banco de Dados
class Flor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    curiosidade = db.Column(db.Text, nullable=False)
    imagem = db.Column(db.String(255), nullable=False)

# Garante que a pasta de uploads exista
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        nome = request.form['nome']
        descricao = request.form['descricao']
        curiosidade = request.form['curiosidade']
        file = request.files['imagem']

        # Verificações de segurança do upload
        if file and allowed_file(file.filename):
            # secure_filename remove caracteres maliciosos do nome do arquivo (ex: ../../)
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Inserção segura no banco via ORM (Previne SQLi)
            nova_flor = Flor(nome=nome, descricao=descricao, curiosidade=curiosidade, imagem=filename)
            db.session.add(nova_flor)
            db.session.commit()
            
            return redirect(url_for('index'))
        else:
            flash("Formato inválido! Envie apenas PNG, JPG ou JPEG.")
            return redirect(url_for('index'))

    # GET: Lista todas as flores cadastradas
    flores = Flor.query.all()
    return render_template('index.html', flores=flores)

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Cria o arquivo SQLite e as tabelas na primeira execução
    app.run(host='0.0.0.0', port=5000, debug=True)

    