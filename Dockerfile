# Dockerfile
FROM python:3.10-slim

# Install git
RUN apt-get update && apt-get install -y git && apt-get clean

# Clone the repository
RUN git clone https://github.com/suryadina/VulnStore-01 /opt/VulnStore-01

# Set working directory
WORKDIR /opt/VulnStore-01

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port
EXPOSE 62292

# Start the app
CMD ["python", "app.py"]
