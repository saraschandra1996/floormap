FROM python:3.10-slim

# Install OS-level dependencies for SNMP and DNS lookups
RUN apt-get update && apt-get install -y snmp host dnsutils && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/floormap

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:8080", "app:app"]
