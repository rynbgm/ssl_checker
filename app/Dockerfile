FROM python:3.10-slim-bullseye

RUN apt-get update && apt-get install -y \
        nmap \
        libssl-dev \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && echo "\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT@SECLEVEL=1" \
        >> /usr/lib/ssl/openssl.cnf

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser && chown -R appuser:appuser /app

USER appuser

CMD ["gunicorn", "-c", "gunicorn_conf.py", "app:app"]