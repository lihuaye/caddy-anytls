#!/usr/bin/env sh
set -eu

SERVER="${ANYTLS_SERVER:-${SERVER:-example.com}}"
PORT="${ANYTLS_PORT:-${PORT:-443}}"
NAME="${ANYTLS_NAME:-${NAME:-caddy-anytls}}"
PASSWORD="${ANYTLS_PASSWORD:-${PASSWORD:-change-this-password}}"
SNI="${ANYTLS_SNI:-${SNI:-$SERVER}}"
SKIP_CERT_VERIFY="${ANYTLS_SKIP_CERT_VERIFY:-${SKIP_CERT_VERIFY:-false}}"
INSECURE="0"
if [ "$SKIP_CERT_VERIFY" = "true" ] || [ "$SKIP_CERT_VERIFY" = "1" ]; then
  INSECURE="1"
fi

URI="$(SERVER="$SERVER" PORT="$PORT" PASSWORD="$PASSWORD" SNI="$SNI" INSECURE="$INSECURE" python3 - <<'PY'
import ipaddress
import os
from urllib.parse import quote, urlencode

server = os.environ["SERVER"]
port = os.environ["PORT"]
password = os.environ["PASSWORD"]
sni = os.environ["SNI"]
insecure = os.environ["INSECURE"]

host = server
try:
    if ipaddress.ip_address(server).version == 6:
        host = f"[{server}]"
except ValueError:
    pass

authority = f"{quote(password, safe='')}@{host}"
if port and port != "443":
    authority = f"{authority}:{port}"

params = {}
if sni and sni != server:
    params["sni"] = sni
if insecure == "1":
    params["insecure"] = "1"

query = urlencode(params)
print(f"anytls://{authority}/" + (f"?{query}" if query else ""))
PY
)"

cat <<EOF
AnyTLS node information

URI:
${URI}

Mihomo:
- name: ${NAME}
  type: anytls
  server: ${SERVER}
  port: ${PORT}
  password: ${PASSWORD}
  sni: ${SNI}
  skip-cert-verify: ${SKIP_CERT_VERIFY}

Surfboard:
${NAME} = anytls, ${SERVER}, ${PORT}, ${PASSWORD}, ${SKIP_CERT_VERIFY}, ${SNI},, true

sing-box outbound:
{
  "type": "anytls",
  "tag": "${NAME}",
  "server": "${SERVER}",
  "server_port": ${PORT},
  "password": "${PASSWORD}",
  "tls": {
    "enabled": true,
    "server_name": "${SNI}",
    "insecure": ${SKIP_CERT_VERIFY}
  }
}
EOF
