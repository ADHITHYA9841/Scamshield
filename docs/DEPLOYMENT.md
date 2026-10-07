# ScamShield Deployment & Self-Hosting Guide

## 1. Local Development (Zero-Config SQLite)

To run the backend locally with built-in SQLite:
```bash
cd backend
pip install -r requirements.txt
python main.py
```
The server will bind to `http://localhost:8000`. Swagger documentation is available at `http://localhost:8000/docs`.

---

## 2. Production Deployment with Docker Compose (PostgreSQL)

To run ScamShield and its isolated PostgreSQL database inside Docker:

```bash
# Clone or enter repository
cd scamshield

# Start containers
docker compose up -d --build
```

Check health status:
```bash
curl http://localhost:8000/api/v1/health
```

View live logs:
```bash
docker compose logs -f scamshield-backend
```

---

## 3. Reverse Proxy & HTTPS (Nginx Example)

```nginx
server {
    listen 443 ssl http2;
    server_name scamshield.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/scamshield.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scamshield.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
