FROM python:3.11-slim

# Install dependencies for Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium

# copy & remove the the 'unsafe' keyword/data
COPY scraper.py.unsafe scraper.py

COPY . .

CMD ["python", "scraper.py"]