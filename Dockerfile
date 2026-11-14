# One image, two roles:
#   docker build -t vulnprio-ai .
#   docker run -p 8501:8501 vulnprio-ai                                   # dashboard
#   docker run -p 8000:8000 vulnprio-ai uvicorn api:app --host 0.0.0.0     # API
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501 8000
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
