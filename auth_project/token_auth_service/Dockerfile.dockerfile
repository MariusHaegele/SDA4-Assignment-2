# Verwende ein schlankes Python-Basisimage
FROM python:3.9-slim

# Setze das Arbeitsverzeichnis
WORKDIR /app

# Kopiere die Requirements-Datei und installiere die Abhängigkeiten
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Kopiere den Rest der Anwendung
COPY . .

# Exponiere den Port, auf dem der Service läuft
EXPOSE 8080

# Starte die Flask-Anwendung
CMD ["python", "app.py"]