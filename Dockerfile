# Dockerfile
FROM python:3.10-slim

# Install update
RUN apt-get update && apt-get install -y && apt-get clean

# Set working directory
WORKDIR /app

# Copy app files to the docker
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port
EXPOSE 62292

# Start the app
CMD ["python", "app.py"]
