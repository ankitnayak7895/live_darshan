# Use official Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy only requirements.txt first (for caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Expose the port your Flask app runs on
EXPOSE 8000

# Run the app using Gunicorn (Flask app object named 'app' in app.py)
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
