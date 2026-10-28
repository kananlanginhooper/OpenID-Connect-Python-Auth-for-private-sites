FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FLASK_APP=idp:create_app IDP_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY idp ./idp
# /data: database, signing key, session secret. /shared: client secrets handed to relying parties.
RUN useradd --uid 10001 --no-create-home idp && mkdir -p /data /shared && chown idp:idp /data /shared
USER idp
EXPOSE 9000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/healthz')"
CMD ["gunicorn", "--preload", "--workers", "2", "--bind", "0.0.0.0:9000", "--access-logfile", "-", "idp:create_app()"]
