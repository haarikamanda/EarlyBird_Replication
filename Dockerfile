FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt pyproject.toml ./
COPY src/ ./src/
COPY scripts/ ./scripts/

RUN pip install --no-cache-dir -e .

# Default: run detection (override with docker run ...)
ENTRYPOINT ["python", "scripts/run_detection.py"]
CMD ["--help"]
