# docker build --tag zeitonline/audisto-exporter:PACKAGEVERSION-DOCKERVERSION .
FROM python:3-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-deps -r requirements.txt
ENTRYPOINT ["audisto_exporter"]
