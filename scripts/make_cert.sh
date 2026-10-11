#!/bin/sh
# Tạo chứng chỉ TLS tự ký cho lab. Dùng: ./make_cert.sh [IP-hoặc-hostname]  (mặc định 127.0.0.1)
H=${1:-127.0.0.1}
case "$H" in *[a-zA-Z]*) SAN="DNS:$H,DNS:localhost,IP:127.0.0.1";; *) SAN="IP:$H,DNS:localhost,IP:127.0.0.1";; esac
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout server.key -out server.crt \
  -subj "/CN=ogk-server" -addext "subjectAltName=$SAN"
echo "Server: uvicorn main:app --ssl-keyfile server.key --ssl-certfile server.crt  (đặt OGK_COOKIE_SECURE=1)"
echo "Agent : agent.py enroll --server https://$H:8000 --code MÃ --ca-cert server.crt   (ghim chứng chỉ)"
