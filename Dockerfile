# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies and curl for Poetry installation
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Upgrade pip before installing Poetry
RUN pip install --upgrade pip

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

# Disable Poetry's virtual environment to install dependencies globally
RUN poetry config virtualenvs.create false

# Copy the pyproject.toml and poetry.lock files first (for dependency caching)
COPY pyproject.toml poetry.lock* /app/

# Install dependencies using Poetry
RUN poetry install --no-root

# Copy the rest of the application code (src and tests) into the container
COPY src/ /app/src/
COPY tests/ /app/tests/

EXPOSE 8501

CMD ["poetry", "run", "streamlit", "run", "src/main.py"]