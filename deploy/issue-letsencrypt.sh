#!/usr/bin/env bash
# Emite certificado Let's Encrypt quando DNS apontar para esta VPS.
set -euo pipefail

EXPECTED_IP="${EXPECTED_IP:-5.252.177.106}"
DOMAIN="antiretest.com"

current_ip="$(dig +short "$DOMAIN" A | head -1)"
if [[ "$current_ip" != "$EXPECTED_IP" ]]; then
  echo "DNS ainda não aponta para $EXPECTED_IP (atual: ${current_ip:-vazio})"
  echo "Configure A record $DOMAIN -> $EXPECTED_IP e rode novamente."
  exit 1
fi

sudo certbot certonly --nginx \
  -d antiretest.com \
  -d www.antiretest.com \
  --non-interactive \
  --agree-tos \
  -m admin@botsloop.com.br

sudo sed -i \
  's|/etc/ssl/antiretest/fullchain.pem|/etc/letsencrypt/live/antiretest.com/fullchain.pem|g; s|/etc/ssl/antiretest/privkey.pem|/etc/letsencrypt/live/antiretest.com/privkey.pem|g' \
  /etc/nginx/sites-available/antiretest.com.conf

sudo nginx -t
sudo systemctl reload nginx
echo "Let's Encrypt ativo para https://$DOMAIN"
