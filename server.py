import ssl
import time
import json
from collections import defaultdict, deque
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

# ---------- Simple in-memory "device" state ----------
STATE = {
    "locked": True,
    "last_actor": None,
    "last_action": None,
    "last_time": None,
}

# ---------- Replay protection (very simple) ----------
# Keep last N nonces per identity for a short window.
NONCES = defaultdict(lambda: deque(maxlen=200))
MAX_SKEW_SECONDS = 30

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def parse_peer_cert_der(request: web.Request):
    """
    Returns cryptography.x509 Certificate or None.
    """
    transport = request.transport
    if not transport:
        return None
    sslobj = transport.get_extra_info("ssl_object")
    if not sslobj:
        return None
    der = sslobj.getpeercert(binary_form=True)
    if not der:
        return None
    return x509.load_der_x509_certificate(der, default_backend())

def get_cn(cert: x509.Certificate) -> str:
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else "unknown"
    except Exception:
        return "unknown"

def real_expired(cert: x509.Certificate) -> bool:
    # cryptography uses aware datetime for not_valid_after in newer versions.
    try:
        return cert.not_valid_after.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    except Exception:
        # fallback safe behavior
        return True

def role_from_cn(cn: str) -> str:
    # Presentation-simple mapping: CN is literally the role name
    cn = cn.lower().strip()
    if cn in ("admin", "resident", "maintenance"):
        return cn
    return "unknown"

def allowed(role: str, action: str) -> bool:
    # action: "lock" | "unlock" | "status"
    if action == "status":
        return role in ("admin", "resident", "maintenance")
    if action == "lock":
        return role in ("admin", "resident", "maintenance")
    if action == "unlock":
        return role in ("admin", "resident")
    return False

def check_replay(cn: str, ts: str, nonce: str) -> bool:
    """
    Returns True if request is OK, False if replay / invalid timestamp.
    """
    if not ts or not nonce:
        return False

    try:
        # client sends UNIX epoch seconds as string
        ts_i = int(ts)
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - ts_i) > MAX_SKEW_SECONDS:
        return False

    key = f"{ts_i}:{nonce}"
    dq = NONCES[cn]
    if key in dq:
        return False
    dq.append(key)
    return True

@web.middleware
async def authz_middleware(request, handler):
    # Require client cert (mTLS is enforced at TLS layer, but we also read it)
    cert = parse_peer_cert_der(request)
    if cert is None:
        return web.json_response({"error": "mTLS required: no client certificate presented"}, status=401)

    cn = get_cn(cert)
    role = role_from_cn(cn)

    # Simulated expired checkbox: client sends header
    simulate_expired = request.headers.get("X-Simulate-Expired", "false").lower() == "true"
    if simulate_expired:
        return web.json_response({"error": "certificate expired (simulated)"}, status=401)

    # Real expiration check too (nice to mention in demo)
    if real_expired(cert):
        return web.json_response({"error": "certificate expired (real check)"}, status=401)

    # Simple replay protection (skip for GET /api/status to keep it easy)
    if request.path in ("/api/lock", "/api/unlock"):
        ts = request.headers.get("X-Timestamp", "")
        nonce = request.headers.get("X-Nonce", "")
        if not check_replay(cn, ts, nonce):
            return web.json_response({"error": "replay / bad timestamp / missing nonce"}, status=401)

    request["identity_cn"] = cn
    request["role"] = role
    return await handler(request)

async def api_status(request: web.Request):
    role = request["role"]
    if not allowed(role, "status"):
        return web.json_response({"error": "forbidden"}, status=403)

    return web.json_response({
        "device": "smartlock-001",
        "locked": STATE["locked"],
        "last_actor": STATE["last_actor"],
        "last_action": STATE["last_action"],
        "last_time": STATE["last_time"],
        "your_role": role,
        "your_cn": request["identity_cn"],
    })

async def api_lock(request: web.Request):
    role = request["role"]
    if not allowed(role, "lock"):
        return web.json_response({"error": "forbidden"}, status=403)

    STATE["locked"] = True
    STATE["last_actor"] = request["identity_cn"]
    STATE["last_action"] = "LOCK"
    STATE["last_time"] = now_iso()
    return await api_status(request)

async def api_unlock(request: web.Request):
    role = request["role"]
    if not allowed(role, "unlock"):
        return web.json_response({"error": "forbidden (maintenance cannot unlock)"}, status=403)

    STATE["locked"] = False
    STATE["last_actor"] = request["identity_cn"]
    STATE["last_action"] = "UNLOCK"
    STATE["last_time"] = now_iso()
    return await api_status(request)

def build_ssl_context():
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain("pki/out/server.crt", "pki/out/server.key")

    # Trust root CA for client cert verification
    ssl_ctx.load_verify_locations(cafile="pki/out/rootCA.crt")
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    # Optional hardening for demo clarity
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ssl_ctx

def main():
    app = web.Application(middlewares=[authz_middleware])
    app.router.add_get("/api/status", api_status)
    app.router.add_post("/api/lock", api_lock)
    app.router.add_post("/api/unlock", api_unlock)

    ssl_ctx = build_ssl_context()
    web.run_app(app, host="127.0.0.1", port=8443, ssl_context=ssl_ctx)

if __name__ == "__main__":
    main()

