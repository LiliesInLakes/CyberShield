FROM python:3.11-slim

# System deps for yara compilation and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    openjdk-17-jdk-headless \
    openjdk-21-jdk-headless \
    git \
    git-lfs \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/apk-sentinel

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Download jadx
RUN mkdir -p tools/jadx/lib && \
    wget -q -O tools/jadx/lib/jadx-1.5.6-all.jar \
    https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6-all.jar

# Environment
ENV JADX_DIR=/opt/apk-sentinel/tools/jadx
ENV JDK17_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV JDK21_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PYTHONPATH=/opt/apk-sentinel

# Verify
RUN python -c "import yara; print('YARA OK')" && \
    python -c "from androguard.core.apk import APK; print('Androguard OK')"

ENTRYPOINT ["python"]
