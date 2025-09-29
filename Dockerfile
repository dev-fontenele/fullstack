<<<<<<< HEAD
FROM python:3.8-slim

# Define o diretório de trabalho
WORKDIR /src

# Copia o arquivo de requisitos
COPY requirements.txt ./

# Instala as dependências Python
=======
FROM python:3.11-slim
WORKDIR /src
COPY requirements.txt requirements.txt

>>>>>>> b3e452e (atualizações do projeto)
RUN pip install --no-cache-dir -r requirements.txt

COPY . /src

EXPOSE 5000

ENV FLASK_RUN_HOST=0.0.0.0

CMD ["flask", "run"]