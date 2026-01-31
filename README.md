
# Secure IoT Smart Lock Simulator (HTTPS + mTLS)
**Course:** Internet Security
**Authors:** La’Ron Latin, Heath Liu
---



## Overview
This project simulates a **secure IoT smart door lock** controlled through a command-and-control API protected by **HTTPS and mutual TLS (mTLS)**. It demonstrates how cryptographic mechanisms apply to real-world IoT systems.
---



## Security Goals
- **Confidentiality:** All traffic encrypted using TLS.
- **Integrity:** Commands cannot be modified in transit.
- **Authentication:** X.509 certificate-based client and server authentication.
- **Authorization:** Server-side role-based access control.
- **Replay Protection:** Commands include timestamps and nonces.
- **Certificate Lifecycle Awareness:** Expired certificates are rejected.
---


## System Architecture
### Components
- **Private PKI**
  - Root CA
  - Server certificate
  - Client certificates (admin, resident, maintenance)
- **Secure API Server**
  - Enforces HTTPS + mTLS
  - Validates certificate chains
  - Extracts identity from certificate CN
  - Applies RBAC



- **GUI Client**
  - Presents client cert during TLS handshake
  - Role selection
  - Expired certificate simulation
  - Lock status UI
---


## Roles and Authorization
| Role        | Lock | Unlock |
|-------------|------|--------|
| Maintenance | Yes  | No     |
| Resident    | Yes  | Yes    |
| Admin       | Yes  | Yes    |
---



## Certificate Expiration Simulation
The GUI includes a **Simulate expired certificate** option that forces the server to reject requests. Demonstrates:
- Operational impact of expiration
- Certificate lifecycle management
- Common PKI failure modes
---



## Replay Attack Protection
Commands include:
- Timestamp
- Cryptographic nonce
Server rejects reused nonces or requests outside the allowed time window.
---



## Project Structure
```
smartlock-demo/
├── server.py
├── gui_client.py
├── requirements.txt
├── out/
└── pki/
    └── out -> ../out
```



---
## Requirements
- Python 3.11+
- OpenSSL
- macOS / Linux
Python packages:
- aiohttp
- cryptography
- requests
---



## Setup Instructions
### 1. Create and activate virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate



```
### 2. Install dependencies
```bash
python -m pip install -r requirements.txt
```



### 3. Verify certificates
```bash
ls out
```
Expected files:
```
rootCA.crt, rootCA.key
server.crt, server.key
admin.crt/.key
resident.crt/.key
maintenance.crt/.key
```
---



## Running the System



### Start the server
```bash
python server.py



```
### Test with curl (mTLS)
```bash
curl --cacert pki/out/rootCA.crt   --cert pki/out/resident.crt --key pki/out/resident.key   https://127.0.0.1:8443/api/status
```



### Launch GUI client
```bash
python gui_client.py
```



---
## Browser Warning
Browsers may display a warning because the server uses a private CA. In production, a public CA or device provisioning trust model is used.



---
## Performance Notes
TLS handshake, certificate parsing, and intentionally simple client design introduce latency, illustrating real cryptographic costs.
