FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    gnupg \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /usr/share/keyrings/trivy.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    > /etc/apt/sources.list.d/trivy.list

RUN apt-get update && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PORT=8080
ENV TRIVY_CACHE_DIR=/tmp/trivy-cache
ENV TRIVY_TIMEOUT_SECONDS=300
ENV TRIVY_SEVERITY=LOW,MEDIUM,HIGH,CRITICAL

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
