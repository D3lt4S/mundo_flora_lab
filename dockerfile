FROM python:3.11-slim

# Criação de um utilizador restrito (Boas práticas de DevSecOps)
RUN useradd -u 8888 secureuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R secureuser:secureuser /app
USER secureuser

EXPOSE 5000

CMD ["python", "app.py"]