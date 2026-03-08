#!/usr/bin/env bash
set -euo pipefail

mkdir -p out
cd out

rm -f *.key *.crt *.csr *.srl *.cnf *.p12

echo "[*] Generating Root CA..."
openssl genrsa -out rootCA.key 4096

cat > root_openssl.cnf <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
C = US
ST = CO
L = Denver
O = SmartLockDemo
OU = PKI
CN = SmartLock Root CA

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
CNF

openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -out rootCA.crt -config root_openssl.cnf

echo "[*] Creating server extensions..."
cat > server_ext.cnf <<'CNF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
CNF

echo "[*] Generating server cert..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -subj "/C=US/ST=CO/L=Denver/O=SmartLockDemo/OU=Server/CN=localhost" \
  -out server.csr
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server_ext.cnf

echo "[*] Creating client extensions..."
cat > client_ext.cnf <<'CNF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CNF

make_client () {
  local CN="$1"
  echo "[*] Generating client cert: $CN"
  openssl genrsa -out "${CN}.key" 2048
  openssl req -new -key "${CN}.key" \
    -subj "/C=US/ST=CO/L=Denver/O=SmartLockDemo/OU=Clients/CN=${CN}" \
    -out "${CN}.csr"
  openssl x509 -req -in "${CN}.csr" -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
    -out "${CN}.crt" -days 365 -sha256 -extfile client_ext.cnf
}

make_client admin
make_client resident
make_client maintenance

echo
echo "[✓] Done. Generated:"
ls -1
