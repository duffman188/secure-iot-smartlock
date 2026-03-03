import json
import ssl
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ---------- Simple in-memory "device" state ----------
STATE = {
    "locked": True,
    "last_actor": None,
    "last_action": None,
    "last_time": None,
}

# ---------- Replay protection ----------
# Keep the last N nonces per identity for a short time window.
NONCES = defaultdict(lambda: deque(maxlen=200))
MAX_SKEW_SECONDS = 30

# ---------- Audit log ----------
AUDIT_LOG_PATH = Path("audit.log")


def now_utc() -> datetime:
    """
    Return the current UTC datetime as a timezone-aware object.
    """
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """
    Return the current UTC time in ISO 8601 format.
    """
    return now_utc().isoformat()


def parse_peer_cert_der(request: web.Request):
    """
    Extract the client certificate from the TLS transport and return it
    as a cryptography.x509.Certificate object. Return None if unavailable.
    """
    transport = request.transport
    if not transport:
        return None

    ssl_object = transport.get_extra_info("ssl_object")
    if not ssl_object:
        return None

    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None

    return x509.load_der_x509_certificate(der, default_backend())


def get_cn(cert: x509.Certificate) -> str:
    """
    Extract the Common Name (CN) from the certificate subject.
    """
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else "unknown"
    except Exception:
        return "unknown"


def get_serial_hex(cert: x509.Certificate) -> str:
    """
    Return the certificate serial number as an uppercase hexadecimal string.
    """
    try:
        return format(cert.serial_number, "X")
    except Exception:
        return "unknown"


def real_expired(cert: x509.Certificate) -> bool:
    """
    Perform a real certificate expiration check.
    """
    try:
        return cert.not_valid_after.replace(tzinfo=timezone.utc) < now_utc()
    except Exception:
        # Fail closed if the certificate validity cannot be evaluated.
        return True


def role_from_cn(cn: str) -> str:
    """
    Map the certificate CN to an application role.
    """
    normalized = cn.lower().strip()
    if normalized in ("admin", "resident", "maintenance"):
        return normalized
    return "unknown"


def allowed(role: str, action: str) -> bool:
    """
    Evaluate whether a role may perform a given action.
    """
    if action == "status":
        return role in ("admin", "resident", "maintenance")
    if action == "lock":
        return role in ("admin", "resident", "maintenance")
    if action == "unlock":
        return role in ("admin", "resident")
    return False


def check_replay(cn: str, ts: str, nonce: str) -> bool:
    """
    Return True if the request is fresh and accepted.
    Return False for replay, invalid timestamp, or missing fields.
    """
    if not ts or not nonce:
        return False

    try:
        ts_value = int(ts)
    except ValueError:
        return False

    now_value = int(time.time())
    if abs(now_value - ts_value) > MAX_SKEW_SECONDS:
        return False

    key = f"{ts_value}:{nonce}"
    bucket = NONCES[cn]

    if key in bucket:
        return False

    bucket.append(key)
    return True


def action_name_from_request(request: web.Request) -> str:
    """
    Convert a request path into a normalized action label for logging.
    """
    if request.path == "/api/status":
        return "status"
    if request.path == "/api/lock":
        return "lock"
    if request.path == "/api/unlock":
        return "unlock"
    return "unknown"


def get_source_ip(request: web.Request) -> str:
    """
    Extract the remote peer IP address if available.
    """
    transport = request.transport
    if not transport:
        return "unknown"

    peer = transport.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 1:
        return str(peer[0])

    return "unknown"


def append_audit_log(
    request: web.Request,
    action: str,
    result: str,
    cert: x509.Certificate = None,
    role: str = None,
    cn: str = None,
) -> None:
    """
    Append a single JSONL audit record.
    """
    if cert is not None:
        cn = cn or get_cn(cert)

    if role is None and cn is not None:
        role = role_from_cn(cn)

    record = {
        "timestamp": now_iso(),
        "client_cn": cn or "unknown",
        "role": role or "unknown",
        "action": action,
        "result": result,
        "source_ip": get_source_ip(request),
        "nonce": request.headers.get("X-Nonce", ""),
        "certificate_serial_number": get_serial_hex(cert) if cert else "unknown",
    }

    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


@web.middleware
async def authz_middleware(request: web.Request, handler):
    """
    Authenticate the client certificate, run replay checks, and populate
    identity fields on the request object before dispatching to handlers.
    """
    action = action_name_from_request(request)

    cert = parse_peer_cert_der(request)
    if cert is None:
        append_audit_log(
            request=request,
            action=action,
            result="denied",
            cert=None,
            role="unknown",
            cn="unknown",
        )
        return web.json_response(
            {"error": "mTLS required: no client certificate presented"},
            status=401,
        )

    cn = get_cn(cert)
    role = role_from_cn(cn)

    request["client_cert"] = cert
    request["identity_cn"] = cn
    request["role"] = role

    simulate_expired = request.headers.get("X-Simulate-Expired", "false").lower() == "true"
    if simulate_expired:
        append_audit_log(
            request=request,
            action=action,
            result="expired_cert",
            cert=cert,
            role=role,
            cn=cn,
        )
        return web.json_response(
            {"error": "certificate expired (simulated)"},
            status=401,
        )

    if real_expired(cert):
        append_audit_log(
            request=request,
            action=action,
            result="expired_cert",
            cert=cert,
            role=role,
            cn=cn,
        )
        return web.json_response(
            {"error": "certificate expired (real check)"},
            status=401,
        )

    if request.path in ("/api/lock", "/api/unlock"):
        ts = request.headers.get("X-Timestamp", "")
        nonce = request.headers.get("X-Nonce", "")
        if not check_replay(cn, ts, nonce):
            append_audit_log(
                request=request,
                action=action,
                result="replay_rejected",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response(
                {"error": "replay / bad timestamp / missing nonce"},
                status=401,
            )

    return await handler(request)


async def api_status(request: web.Request):
    """
    Return the current lock state if the caller is authorized.
    """
    role = request["role"]
    cn = request["identity_cn"]
    cert = request["client_cert"]

    if not allowed(role, "status"):
        append_audit_log(
            request=request,
            action="status",
            result="denied",
            cert=cert,
            role=role,
            cn=cn,
        )
        return web.json_response({"error": "forbidden"}, status=403)

    append_audit_log(
        request=request,
        action="status",
        result="allowed",
        cert=cert,
        role=role,
        cn=cn,
    )

    return web.json_response(
        {
            "device": "smartlock-001",
            "locked": STATE["locked"],
            "last_actor": STATE["last_actor"],
            "last_action": STATE["last_action"],
            "last_time": STATE["last_time"],
            "your_role": role,
            "your_cn": cn,
        }
    )


async def api_lock(request: web.Request):
    """
    Lock the device if the caller is authorized.
    """
    role = request["role"]
    cn = request["identity_cn"]
    cert = request["client_cert"]

    if not allowed(role, "lock"):
        append_audit_log(
            request=request,
            action="lock",
            result="denied",
            cert=cert,
            role=role,
            cn=cn,
        )
        return web.json_response({"error": "forbidden"}, status=403)

    STATE["locked"] = True
    STATE["last_actor"] = cn
    STATE["last_action"] = "LOCK"
    STATE["last_time"] = now_iso()

    append_audit_log(
        request=request,
        action="lock",
        result="allowed",
        cert=cert,
        role=role,
        cn=cn,
    )

    return await api_status(request)


async def api_unlock(request: web.Request):
    """
    Unlock the device if the caller is authorized.
    """
    role = request["role"]
    cn = request["identity_cn"]
    cert = request["client_cert"]

    if not allowed(role, "unlock"):
        append_audit_log(
            request=request,
            action="unlock",
            result="denied",
            cert=cert,
            role=role,
            cn=cn,
        )
        return web.json_response(
            {"error": "forbidden (maintenance cannot unlock)"},
            status=403,
        )

    STATE["locked"] = False
    STATE["last_actor"] = cn
    STATE["last_action"] = "UNLOCK"
    STATE["last_time"] = now_iso()

    append_audit_log(
        request=request,
        action="unlock",
        result="allowed",
        cert=cert,
        role=role,
        cn=cn,
    )

    return await api_status(request)


def build_ssl_context():
    """
    Create the TLS context used by the aiohttp server.
    """
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain("pki/out/server.crt", "pki/out/server.key")

    # Trust the private root CA for client certificate verification.
    ssl_ctx.load_verify_locations(cafile="pki/out/rootCA.crt")
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    # Keep the demo simple but avoid obsolete TLS versions.
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ssl_ctx


def main():
    """
    Start the HTTPS server.
    """
    app = web.Application(middlewares=[authz_middleware])
    app.router.add_get("/api/status", api_status)
    app.router.add_post("/api/lock", api_lock)
    app.router.add_post("/api/unlock", api_unlock)

    ssl_ctx = build_ssl_context()
    web.run_app(app, host="127.0.0.1", port=8443, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()