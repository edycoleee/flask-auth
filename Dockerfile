# Gunakan image Python slim
FROM python:3.10-slim

# Set environment variable
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Salin semua file
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port Flask
EXPOSE 5000

# Jalankan Flask
CMD ["python", "app.py"]
