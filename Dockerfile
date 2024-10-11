# Base image with Python
FROM python:3.13-slim

# Set working directory inside the container
WORKDIR /app

# Copy the requirements file to install dependencies
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app code into the container
COPY ovh-dns-updater.py .

# Expose default port (optional if you plan to run as a service)
# EXPOSE 8080

# Set environment variables for better execution (optional)
ENV PYTHONUNBUFFERED=1

# Set the entrypoint to run the Python script
ENTRYPOINT ["python", "ovh-dns-updater.py"]
